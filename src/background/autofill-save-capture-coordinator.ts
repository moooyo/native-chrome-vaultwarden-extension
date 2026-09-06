import type { SymmetricKey } from '../core/crypto/keys.js';
import { AppError } from '../core/errors.js';
import { getBaseDomain } from '../core/vault/domain.js';
import type { KeyValueStore } from '../platform/store.js';
import type { AutofillSaveCaptureSubmission } from '../messaging/protocol.js';
import {
  MAX_AUTOFILL_PENDING_SAVE_TTL_MS,
  type AutofillPendingSaveCredentials,
  type AutofillPendingSaveDocumentContext,
  type AutofillPendingSaveEvaluator,
  type AutofillPendingSaveInput,
  type AutofillPendingSavePublicPrompt,
  type TakenAutofillPendingSave,
  type AutofillUnconfirmedSaveMetadata,
  type AutofillPendingSaveStore,
} from './autofill-pending-save-store.js';
import type {
  AutofillUsernameStageContext,
  AutofillUsernameStageInput,
  AutofillUsernameStageStore,
} from './autofill-username-stage-store.js';

export const AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY = 'autofillSaveCaptureNetworkJournal';
export const AUTOFILL_SAVE_CAPTURE_ALARM = 'autofillSaveCaptureNetwork';
export const AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION = 3 as const;
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

export interface AutofillSaveCaptureRuntimeActivation {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly frameUrl: string;
  readonly runtimeIncarnation: string;
  readonly previousRuntimeIncarnation?: string;
}

export interface AutofillSaveCaptureRuntimeAuthority {
  /** A synchronous fence for a runtime observed in the persisted journal. */
  readonly assertCurrent: () => void;
}

export interface AutofillSaveCaptureBeforeRequestAdmission {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId?: string;
  readonly sourceDocumentUrl?: string;
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
    | 'claim'
    | 'take'
    | 'dismiss'
  >;
  /** Returns a fresh owned key copy. The capture store consumes and zeroes it. */
  readonly loadUserKey: (metadata: AutofillUnconfirmedSaveMetadata) => Promise<SymmetricKey | undefined>;
  readonly assertCurrent?: (metadata: AutofillUnconfirmedSaveMetadata) => void;
  readonly onConfirmed?: (metadata: AutofillUnconfirmedSaveMetadata) => void | Promise<void>;
  readonly clearUsernameRuntime?: (
    tabId: number,
    frameId: number,
    documentId: string,
    runtimeIncarnation: string,
  ) => void | Promise<void>;
  readonly usernameStages?: Pick<
    AutofillUsernameStageStore,
    'stage' | 'consume' | 'clearRuntime' | 'clearTab' | 'clear'
  >;
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
  readonly runtimeIncarnation: string;
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
  readonly runtimeIncarnation: string;
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
  allowGetTerminal: boolean;
  continuation?: {
    readonly statusCode: 307 | 308;
    readonly redirectedAt: number;
    readonly expectedUrlFingerprint: string;
  };
}

interface TerminalOutcome {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
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
  readonly statusCode: number;
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
  runtimeFenceUntil: number;
  captures: CaptureRecord[];
  requests: RequestRecord[];
  outcomes: TerminalOutcome[];
  activeRuntimes: ActiveRuntimeRecord[];
  retiredRuntimes: RetiredRuntimeRecord[];
  admissions: PendingBeforeRequestAdmission[];
}

interface StoredJournal {
  readonly schemaVersion: typeof AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION;
  readonly revision: number;
  readonly blockedUntil: number;
  readonly runtimeFenceUntil: number;
  readonly captures: readonly CaptureRecord[];
  readonly requests: readonly RequestRecord[];
  readonly outcomes: readonly TerminalOutcome[];
  readonly activeRuntimes: readonly ActiveRuntimeRecord[];
  readonly retiredRuntimes: readonly RetiredRuntimeRecord[];
  readonly admissions: readonly PendingBeforeRequestAdmission[];
}

interface ActiveRuntimeRecord {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly documentUrlFingerprint: string;
  readonly activatedAt: number;
}

interface RetiredRuntimeRecord {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly retiredAt: number;
  expiresAt: number;
  cleanupPending: boolean;
}

interface PendingBeforeRequestAdmission {
  readonly admissionId: string;
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  status: 'pending' | 'failed';
  readonly enteredAt: number;
  readonly expiresAt: number;
}

interface VolatileRetiredRuntimeRecord {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly expiresAt: number;
}

interface SaveCaptureConfirmationFence {
  readonly generation: object;
  readonly sequence: number;
}

interface NetworkConfirmationWindow {
  readonly opensAt: number;
  readonly closesAt: number;
}

interface InFlightStageInterest {
  readonly frameKey: string;
}

interface SaveCaptureRuntimeOperationFence {
  readonly global: object;
  readonly tabId: number;
  readonly tab: object;
  readonly frameKey: string;
  readonly frame: object;
}

type CanonicalRuntimeActivation = AutofillSaveCaptureRuntimeActivation;

interface CanonicalBeforeRequestAdmission {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId?: string;
  readonly sourceDocumentUrl?: string;
  readonly enteredAt: number;
  readonly expiresAt: number;
}

type PreparedBeforeRequest = Omit<RequestRecord, 'runtimeIncarnation'>;

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
  readonly #clearUsernameRuntime: NonNullable<AutofillSaveCaptureCoordinatorOptions['clearUsernameRuntime']>;
  readonly #usernameStages: AutofillSaveCaptureCoordinatorOptions['usernameStages'];
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
  #confirmationGeneration: object = {};
  #confirmationSequence = 0;
  #globalConfirmationSequence = 0;
  readonly #runtimeConfirmationTabSequences = new Map<number, number>();
  readonly #runtimeConfirmationFrameSequences = new Map<string, number>();
  readonly #networkConfirmationTabSequences = new Map<number, number>();
  readonly #networkConfirmationFrameSequences = new Map<string, number>();
  readonly #networkConfirmationWindows = new Map<string, readonly NetworkConfirmationWindow[]>();
  readonly #networkConfirmationRequestIds = new Set<string>();
  readonly #inFlightStageInterests = new Set<InFlightStageInterest>();
  #networkConfirmationWindowsKnown = false;
  #runtimeOperationGlobalFence: object = {};
  readonly #runtimeOperationTabFences = new Map<number, object>();
  readonly #runtimeOperationFrameFences = new Map<string, object>();
  readonly #volatileRetiredRuntimes = new Map<string, VolatileRetiredRuntimeRecord>();
  #volatileRuntimeFenceUntil = 0;

  constructor(options: AutofillSaveCaptureCoordinatorOptions) {
    if (!options || typeof options.store?.get !== 'function' || typeof options.store?.set !== 'function'
        || typeof options.captures?.putUnconfirmed !== 'function'
        || typeof options.captures?.confirmUnconfirmed !== 'function'
        || typeof options.captures?.discardCapture !== 'function'
        || typeof options.captures?.captureState !== 'function'
        || typeof options.captures?.captureMetadata !== 'function'
        || typeof options.captures?.listUnconfirmed !== 'function'
        || typeof options.captures?.claim !== 'function'
        || typeof options.captures?.take !== 'function'
        || typeof options.captures?.dismiss !== 'function'
        || typeof options.loadUserKey !== 'function') {
      throw new TypeError('Save-capture coordinator dependencies are invalid');
    }
    this.#store = options.store;
    this.#captures = options.captures;
    this.#loadUserKey = options.loadUserKey;
    this.#assertCurrent = options.assertCurrent ?? (() => {});
    this.#onConfirmed = options.onConfirmed ?? (() => {});
    this.#clearUsernameRuntime = options.clearUsernameRuntime ?? (() => {});
    this.#usernameStages = options.usernameStages;
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

  activateRuntime(input: AutofillSaveCaptureRuntimeActivation): Promise<boolean> {
    const activation = canonicalRuntimeActivation(input);
    if (activation.frameId === 0) {
      this.#bumpRuntimeConfirmationTab(activation.tabId);
      this.#bumpRuntimeOperationTab(activation.tabId);
    } else {
      this.#bumpRuntimeConfirmationFrame(activation.tabId, activation.frameId);
      this.#bumpRuntimeOperationFrame(activation.tabId, activation.frameId);
    }
    const confirmationFence = this.#captureConfirmationFence();
    return this.#serialize(async () => {
      const documentUrlFingerprint = (await documentUrlBinding(
        activation.frameUrl,
      )).documentUrlFingerprint;
      const state = await this.#read();
      await this.#reconcileCaptureStore(state);
      if (state.runtimeFenceUntil > this.#time() || this.#volatileRuntimeFenceActive()) {
        await this.#settle(state, confirmationFence);
        return false;
      }
      const pendingDocumentCleanup = (): boolean => state.retiredRuntimes.some((candidate) => (
        sameRuntimeDocument(candidate, activation) && candidate.cleanupPending
      ));
      if (pendingDocumentCleanup()) {
        await this.#evaluate(state, confirmationFence);
        if (pendingDocumentCleanup()) {
          await this.#write(state);
          await this.#notifyConfirmed(state);
          await this.#write(state);
          this.#reschedule(state);
          return false;
        }
      }
      if (state.retiredRuntimes.some((candidate) => (
        sameRuntimeDocument(candidate, activation)
        && candidate.runtimeIncarnation === activation.runtimeIncarnation
      ))) {
        await this.#settle(state, confirmationFence);
        return false;
      }
      const existing = state.activeRuntimes.find((candidate) => sameRuntimeDocument(candidate, activation));
      let volatileRetirementKey: string | undefined;
      if (existing?.runtimeIncarnation === activation.runtimeIncarnation) {
        if (this.#runtimeRetired(state, existing)) {
          await this.#settle(state, confirmationFence);
          return false;
        }
        if (existing.documentUrlFingerprint !== documentUrlFingerprint) {
          state.activeRuntimes = state.activeRuntimes.map((candidate) => candidate === existing
            ? Object.freeze({
                ...existing,
                documentUrlFingerprint,
                activatedAt: this.#time(),
              })
            : candidate);
        }
        if (activation.frameId === 0) {
          state.activeRuntimes = state.activeRuntimes.filter((candidate) => (
            candidate.tabId !== activation.tabId || candidate.frameId === 0
          ));
        }
        await this.#settle(state, confirmationFence);
        return true;
      }
      if (activation.previousRuntimeIncarnation === undefined) {
        if (existing || state.activeRuntimes.some((candidate) => (
          candidate.tabId === activation.tabId && candidate.frameId === activation.frameId
        ))) {
          await this.#settle(state, confirmationFence);
          return false;
        }
      } else {
        if (existing && existing.runtimeIncarnation !== activation.previousRuntimeIncarnation) {
          await this.#settle(state, confirmationFence);
          return false;
        }
        let retired = state.retiredRuntimes.find((candidate) => (
          sameRuntimeDocument(candidate, activation)
          && candidate.runtimeIncarnation === activation.previousRuntimeIncarnation
        ));
        if (!retired) {
          if (state.retiredRuntimes.length >= this.#maxRequests) {
            await this.#blockAll(state, safeDeadline(this.#time(), this.#networkTtlMs));
            await this.#settle(state, confirmationFence);
            return false;
          }
          volatileRetirementKey = this.#rememberVolatileRetirement({
            tabId: activation.tabId,
            frameId: activation.frameId,
            documentId: activation.documentId,
            runtimeIncarnation: activation.previousRuntimeIncarnation,
          });
          if (!volatileRetirementKey) {
            state.runtimeFenceUntil = Math.max(
              state.runtimeFenceUntil,
              safeDeadline(this.#time(), this.#networkTtlMs),
            );
            await this.#blockAll(state, state.runtimeFenceUntil);
            await this.#settle(state, confirmationFence);
            return false;
          }
          const retiredAt = this.#time();
          retired = {
            tabId: activation.tabId,
            frameId: activation.frameId,
            documentId: activation.documentId,
            runtimeIncarnation: activation.previousRuntimeIncarnation,
            retiredAt,
            expiresAt: safeDeadline(retiredAt, this.#networkTtlMs),
            cleanupPending: true,
          };
          state.retiredRuntimes.push(retired);
          // Persist the tombstone before touching stores outside this journal. A retry can finish the
          // idempotent cleanup, but no delayed stage can cross this write-ahead fence.
          await this.#write(state);
          this.#reschedule(state);
        }
        if (retired.cleanupPending) {
          await this.#retireRuntimeState(state, activation, activation.previousRuntimeIncarnation);
          await this.#write(state);
          this.#reschedule(state);
          await this.#clearUsernameRuntime(
            activation.tabId,
            activation.frameId,
            activation.documentId,
            activation.previousRuntimeIncarnation,
          );
          await this.#usernameStages?.clearRuntime(
            activation.tabId,
            activation.frameId,
            activation.documentId,
            activation.previousRuntimeIncarnation,
          );
          retired.cleanupPending = false;
        }
      }

      state.activeRuntimes = state.activeRuntimes.filter((candidate) => (
        candidate.tabId !== activation.tabId
        || (activation.frameId !== 0 && candidate.frameId !== activation.frameId)
      ));
      if (state.activeRuntimes.length >= this.#maxRequests) {
        await this.#blockAll(state, safeDeadline(this.#time(), this.#networkTtlMs));
        await this.#settle(state, confirmationFence);
        if (volatileRetirementKey) this.#volatileRetiredRuntimes.delete(volatileRetirementKey);
        return false;
      }
      state.activeRuntimes.push(Object.freeze({
        tabId: activation.tabId,
        frameId: activation.frameId,
        documentId: activation.documentId,
        runtimeIncarnation: activation.runtimeIncarnation,
        documentUrlFingerprint,
        activatedAt: this.#time(),
      }));
      await this.#settle(state, confirmationFence);
      if (volatileRetirementKey) this.#volatileRetiredRuntimes.delete(volatileRetirementKey);
      return true;
    });
  }

  beginBeforeRequest(
    input: AutofillSaveCaptureBeforeRequestAdmission,
  ): Promise<string | undefined> {
    const admission = canonicalBeforeRequestAdmission(input, this.#networkTtlMs);
    this.#bumpNetworkConfirmationFrame(
      admission.tabId,
      admission.frameId,
      admission.enteredAt,
      admission.requestId,
    );
    const confirmationFence = this.#captureConfirmationFence();
    return this.#serialize(async () => {
      const documentUrlFingerprint = admission.sourceDocumentUrl
        ? (await documentUrlBinding(admission.sourceDocumentUrl)).documentUrlFingerprint
        : undefined;
      const state = await this.#read();
      await this.#reconcileCaptureStore(state);
      const candidates = state.activeRuntimes.filter((runtime) => (
        runtime.tabId === admission.tabId
        && runtime.frameId === admission.frameId
        && (admission.documentId === undefined || runtime.documentId === admission.documentId)
        && (documentUrlFingerprint === undefined
          || runtime.documentUrlFingerprint === documentUrlFingerprint)
      ));
      if (candidates.length !== 1) return undefined;
      const runtime = candidates[0]!;
      if (this.#runtimeRetired(state, runtime)) return undefined;
      if (state.admissions.length >= this.#maxRequests) {
        await this.#blockAll(state, admission.expiresAt);
        await this.#write(state);
        this.#reschedule(state);
        return undefined;
      }
      const admissionId = this.#freshAdmissionId(state);
      state.admissions.push({
        admissionId,
        requestId: admission.requestId,
        tabId: runtime.tabId,
        frameId: runtime.frameId,
        documentId: runtime.documentId,
        runtimeIncarnation: runtime.runtimeIncarnation,
        status: 'pending',
        enteredAt: admission.enteredAt,
        expiresAt: admission.expiresAt,
      });
      await this.#evaluate(state, confirmationFence);
      await this.#write(state);
      this.#reschedule(state);
      return admissionId;
    });
  }

  async resolveBeforeRequest(
    admissionIdInput: string,
    input: AutofillSaveCaptureBeforeRequest,
  ): Promise<void> {
    const admissionId = uuid(admissionIdInput, 'admissionId');
    const parsed = await parseBeforeRequest(input, this.#networkTtlMs);
    return this.#mutate(async (state) => {
      const admission = this.#takeAdmission(state, admissionId);
      if (!admission) return;
      if (admission.status !== 'pending'
          || parsed.requestId !== admission.requestId
          || parsed.tabId !== admission.tabId
          || parsed.frameId !== admission.frameId
          || parsed.documentId !== admission.documentId
          || parsed.startedAt !== admission.enteredAt
          || this.#runtimeRetired(state, admission)) {
        admission.status = 'failed';
        state.admissions.push(admission);
        await this.#failAdmission(state, admission);
        return;
      }
      await this.#addRequest(state, {
        ...parsed,
        runtimeIncarnation: admission.runtimeIncarnation,
      });
    });
  }

  async failBeforeRequest(admissionIdInput: string): Promise<void> {
    const admissionId = uuid(admissionIdInput, 'admissionId');
    return this.#mutate(async (state) => {
      const admission = state.admissions.find((candidate) => candidate.admissionId === admissionId);
      if (!admission) return;
      admission.status = 'failed';
      await this.#failAdmission(state, admission);
    });
  }

  isRuntimeCurrent(
    tabIdInput: number,
    frameIdInput: number,
    documentIdInput: string,
    runtimeIncarnationInput: string,
  ): Promise<boolean> {
    return this.captureRuntimeAuthority(
      tabIdInput,
      frameIdInput,
      documentIdInput,
      runtimeIncarnationInput,
    ).then((authority) => {
      if (!authority) return false;
      try {
        authority.assertCurrent();
        return true;
      } catch {
        return false;
      }
    });
  }

  captureRuntimeAuthority(
    tabIdInput: number,
    frameIdInput: number,
    documentIdInput: string,
    runtimeIncarnationInput: string,
  ): Promise<AutofillSaveCaptureRuntimeAuthority | undefined> {
    const tabId = nonNegativeInteger(tabIdInput, 'tabId');
    const frameId = nonNegativeInteger(frameIdInput, 'frameId');
    const documentId = opaqueId(documentIdInput, 'documentId', MAX_DOCUMENT_ID_LENGTH);
    const runtimeIncarnation = uuid(runtimeIncarnationInput, 'runtimeIncarnation');
    // Capture before queueing: a later navigation can revoke this read before its turn begins.
    const fence = this.#captureRuntimeOperationFence(tabId, frameId);
    return this.#serialize(async () => {
      const state = await this.#read();
      const runtime = state.activeRuntimes.find((candidate) => (
        candidate.tabId === tabId
        && candidate.frameId === frameId
        && candidate.documentId === documentId
        && candidate.runtimeIncarnation === runtimeIncarnation
      ));
      if (!runtime || state.runtimeFenceUntil > this.#time() || this.#runtimeRetired(state, runtime)
          || !this.#runtimeOperationFenceCurrent(fence)) return undefined;
      return Object.freeze({
        assertCurrent: (): void => {
          if (!this.#runtimeOperationFenceCurrent(fence)) {
            throw new AppError('denied', 'Save-capture runtime authority changed');
          }
        },
      });
    });
  }

  getRuntimeIncarnation(
    tabIdInput: number,
    frameIdInput: number,
    documentIdInput: string,
  ): Promise<string | undefined> {
    const tabId = nonNegativeInteger(tabIdInput, 'tabId');
    const frameId = nonNegativeInteger(frameIdInput, 'frameId');
    const documentId = opaqueId(documentIdInput, 'documentId', MAX_DOCUMENT_ID_LENGTH);
    return this.#serialize(async () => {
      const state = await this.#read();
      const matches = state.activeRuntimes.filter((candidate) => (
        candidate.tabId === tabId
        && candidate.frameId === frameId
        && candidate.documentId === documentId
        && !this.#runtimeRetired(state, candidate)
      ));
      return matches.length === 1 ? matches[0]!.runtimeIncarnation : undefined;
    });
  }

  noteDocumentNavigation(
    tabIdInput: number,
    frameIdInput: number,
    documentIdInput?: string,
  ): Promise<void> {
    const tabId = nonNegativeInteger(tabIdInput, 'tabId');
    const frameId = nonNegativeInteger(frameIdInput, 'frameId');
    const documentId = documentIdInput === undefined
      ? undefined
      : opaqueId(documentIdInput, 'documentId', MAX_DOCUMENT_ID_LENGTH);
    if (frameId === 0) {
      this.#bumpRuntimeConfirmationTab(tabId);
      this.#bumpRuntimeOperationTab(tabId);
    } else {
      this.#bumpRuntimeConfirmationFrame(tabId, frameId);
      this.#bumpRuntimeOperationFrame(tabId, frameId);
    }
    return this.#mutate((state) => {
      state.activeRuntimes = state.activeRuntimes.filter((runtime) => (
        runtime.tabId !== tabId || (frameId === 0
          ? runtime.frameId === 0 && documentId !== undefined && runtime.documentId === documentId
          : runtime.frameId !== frameId
            || (documentId !== undefined && runtime.documentId === documentId))
      ));
      for (const [key, runtime] of this.#volatileRetiredRuntimes) {
        const survivesNavigation = frameId === 0
          ? runtime.frameId === 0 && documentId !== undefined && runtime.documentId === documentId
          : runtime.frameId !== frameId
            || (documentId !== undefined && runtime.documentId === documentId);
        if (runtime.tabId === tabId && !survivesNavigation) {
          this.#volatileRetiredRuntimes.delete(key);
        }
      }
    });
  }

  stageUsername(input: AutofillUsernameStageInput): Promise<void> {
    if (!this.#usernameStages) return Promise.reject(new Error('Username stage store is unavailable'));
    return this.#serialize(async () => {
      const state = await this.#read();
      const runtime = state.activeRuntimes.find((candidate) => (
        candidate.tabId === input.tabId
        && candidate.frameId === input.frameId
        && candidate.documentId === input.documentId
        && candidate.runtimeIncarnation === input.runtimeIncarnation
      ));
      if (!runtime || this.#runtimeRetired(state, runtime)) {
        throw new Error('Username stage runtime is stale');
      }
      await this.#usernameStages!.stage(input);
    });
  }

  consumeUsername(context: AutofillUsernameStageContext): Promise<string | undefined> {
    if (!this.#usernameStages) return Promise.reject(new Error('Username stage store is unavailable'));
    return this.#serialize(async () => {
      const state = await this.#read();
      const runtime = state.activeRuntimes.find((candidate) => (
        candidate.tabId === context.tabId
        && candidate.frameId === context.frameId
        && candidate.documentId === context.documentId
        && candidate.runtimeIncarnation === context.runtimeIncarnation
      ));
      if (!runtime || this.#runtimeRetired(state, runtime)) return undefined;
      return this.#usernameStages!.consume(context);
    });
  }

  async claimPendingSave(
    context: AutofillPendingSaveDocumentContext,
    ownedUserKey: SymmetricKey,
    evaluate: AutofillPendingSaveEvaluator,
    captureId?: string,
  ): Promise<AutofillPendingSavePublicPrompt> {
    const runtimeFence = this.#captureRuntimeOperationFence(context.tabId, context.frameId);
    try {
      return await this.#serialize(async () => {
        const state = await this.#read();
        if (!this.#pendingSaveRuntimeCurrent(state, context)) {
          throw new Error('Pending-save runtime is stale');
        }
        const assertFence = (): void => {
          if (!this.#runtimeOperationFenceCurrent(runtimeFence)) {
            throw new Error('Pending-save runtime fence changed');
          }
        };
        const prompt = await this.#captures.claim(
          context,
          ownedUserKey,
          evaluate,
          captureId,
          assertFence,
        );
        assertFence();
        return prompt;
      });
    } finally {
      zeroOwnedUserKey(ownedUserKey);
    }
  }

  async takePendingSave(
    promptId: string,
    context: AutofillPendingSaveDocumentContext,
    ownedUserKey: SymmetricKey,
  ): Promise<TakenAutofillPendingSave | undefined> {
    const runtimeFence = this.#captureRuntimeOperationFence(context.tabId, context.frameId);
    try {
      return await this.#serialize(async () => {
        const state = await this.#read();
        if (!this.#pendingSaveRuntimeCurrent(state, context)) return undefined;
        const assertFence = (): void => {
          if (!this.#runtimeOperationFenceCurrent(runtimeFence)) {
            throw new Error('Pending-save runtime fence changed');
          }
        };
        const taken = await this.#captures.take(promptId, context, ownedUserKey, assertFence);
        assertFence();
        return taken;
      });
    } finally {
      zeroOwnedUserKey(ownedUserKey);
    }
  }

  dismissPendingSave(
    promptId: string,
    context: AutofillPendingSaveDocumentContext,
  ): Promise<boolean> {
    const runtimeFence = this.#captureRuntimeOperationFence(context.tabId, context.frameId);
    return this.#serialize(async () => {
      const state = await this.#read();
      if (!this.#pendingSaveRuntimeCurrent(state, context)) return false;
      const assertFence = (): void => {
        if (!this.#runtimeOperationFenceCurrent(runtimeFence)) {
          throw new Error('Pending-save runtime fence changed');
        }
      };
      const dismissed = await this.#captures.dismiss(promptId, context, assertFence);
      assertFence();
      return dismissed;
    });
  }

  #pendingSaveRuntimeCurrent(
    state: JournalState,
    context: AutofillPendingSaveDocumentContext,
  ): boolean {
    const runtime = state.activeRuntimes.find((candidate) => (
      candidate.tabId === context.tabId
      && candidate.frameId === context.frameId
      && candidate.documentId === context.documentId
      && candidate.runtimeIncarnation === context.runtimeIncarnation
    ));
    return Boolean(runtime && !this.#runtimeRetired(state, runtime));
  }

  async stage(
    input: AutofillPendingSaveInput,
    credentials: AutofillPendingSaveCredentials,
    ownedUserKey: SymmetricKey,
    submissionInput: AutofillSaveCaptureSubmission,
  ): Promise<AutofillUnconfirmedSaveMetadata> {
    let stageInterest: InFlightStageInterest | undefined;
    try {
      const submission = parseSubmission(submissionInput);
      const tabId = nonNegativeInteger(input.tabId, 'tabId');
      const frameId = nonNegativeInteger(input.frameId, 'frameId');
      stageInterest = this.#beginInFlightStageInterest(tabId, frameId);
      const runtimeFence = this.#captureRuntimeOperationFence(tabId, frameId);
      const confirmationFence = this.#captureConfirmationFence();
      return await this.#serialize(async () => {
        const assertFence = (): void => {
          if (!this.#runtimeOperationFenceCurrent(runtimeFence)) {
            throw new Error('Save-capture runtime fence changed');
          }
        };
        const source = await documentUrlBinding(input.sourceUrl);
        const state = await this.#read();
        await this.#reconcileCaptureStore(state);
        const runtime = state.activeRuntimes.find((candidate) => (
          candidate.tabId === input.tabId
          && candidate.frameId === input.frameId
          && candidate.documentId === input.sourceDocumentId
          && candidate.runtimeIncarnation === input.runtimeIncarnation
          && candidate.documentUrlFingerprint === source.documentUrlFingerprint
        ));
        if (!runtime || this.#runtimeRetired(state, runtime) || state.blockedUntil > this.#time()) {
          throw new Error('Save-capture runtime is stale');
        }
        const metadata = await this.#captures.putUnconfirmed(
          input,
          credentials,
          ownedUserKey,
          assertFence,
        );
        try {
          assertFence();
          const captureRecord = await createCaptureRecord(metadata, submission);
          assertFence();
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
          await this.#evaluate(state, confirmationFence);
          await this.#write(state);
          await this.#notifyConfirmed(state);
          await this.#write(state);
          this.#reschedule(state);
          return metadata;
        } catch (error) {
          await this.#captures.discardCapture(metadata.captureId).catch(() => false);
          throw error;
        }
      });
    } finally {
      if (stageInterest) this.#endInFlightStageInterest(stageInterest);
      zeroOwnedUserKey(ownedUserKey);
    }
  }

  async observeBeforeRequest(input: AutofillSaveCaptureBeforeRequest): Promise<void> {
    const eventTime = timestamp(input.timeStamp, 'timeStamp');
    this.#bumpNetworkConfirmationFrame(
      nonNegativeInteger(input.tabId, 'tabId'),
      nonNegativeInteger(input.frameId, 'frameId'),
      eventTime,
      typeof input.requestId === 'string' ? input.requestId : undefined,
    );
    return this.#mutate(async (state) => {
      let prepared: PreparedBeforeRequest;
      try {
        prepared = await parseBeforeRequest(input, this.#networkTtlMs);
      } catch {
        await this.#blockAll(state, safeDeadline(this.#time(), this.#networkTtlMs));
        return;
      }
      const runtime = uniqueRuntimeForPreparedRequest(state, prepared);
      if (!runtime) {
        await this.#blockAll(state, prepared.expiresAt);
        return;
      }
      await this.#addRequest(state, { ...prepared, runtimeIncarnation: runtime.runtimeIncarnation });
    });
  }

  async observeRedirect(input: AutofillSaveCaptureRedirectRequest): Promise<void> {
    const eventTime = timestamp(input.timeStamp, 'timeStamp');
    this.#bumpNetworkConfirmationFrame(
      nonNegativeInteger(input.tabId, 'tabId'),
      nonNegativeInteger(input.frameId, 'frameId'),
      eventTime,
      typeof input.requestId === 'string' ? input.requestId : undefined,
    );
    return this.#mutate(async (state) => {
      let redirect: PreparedRedirect;
      try {
        redirect = await parseRedirectRequest(input, this.#networkTtlMs);
      } catch {
        await this.#blockAll(state, safeDeadline(this.#time(), this.#networkTtlMs));
        return;
      }
      const request = state.requests.find((candidate) => candidate.requestId === redirect.requestId);
      const acceptsRedirect = request?.phase === 'started'
        || (request?.phase === 'redirected'
          && request.continuation === undefined
          && request.allowGetTerminal
          && redirect.method === 'GET');
      if (!request || !acceptsRedirect
          || !terminalIdentityMatches(redirect, request)
          || redirect.type !== request.type
          || redirect.urlFingerprint !== request.currentUrlFingerprint
          || (redirect.method !== request.method
            && !(request.allowGetTerminal && redirect.method === 'GET'))
          || redirect.timeStamp < request.startedAt
          || request.redirectCount >= MAX_REDIRECTS
          || !sameSiteBinding(
            request.documentOrigin,
            request.documentSite,
            redirect.redirectOrigin,
            redirect.redirectSite,
          )) {
        if (request) request.phase = 'failed';
        else if (MUTATION_METHODS.has(redirect.method)) {
          const runtimeIncarnation = runtimeForTerminal(state, redirect);
          if (!runtimeIncarnation) return;
          this.#upsertOutcome(state, {
          requestId: redirect.requestId,
          tabId: redirect.tabId,
          frameId: redirect.frameId,
          documentId: redirect.documentId,
          runtimeIncarnation,
          urlFingerprint: redirect.urlFingerprint,
          method: redirect.method,
          type: redirect.type,
          completedAt: redirect.timeStamp,
          expiresAt: redirect.expiresAt,
          phase: 'failed',
          });
        }
        return;
      }
      request.currentOrigin = redirect.redirectOrigin;
      request.currentSite = redirect.redirectSite;
      request.currentUrlFingerprint = redirect.redirectUrlFingerprint;
      request.redirectCount += 1;
      request.phase = 'redirected';
      const preservesTrackedMutation = (redirect.statusCode === 307 || redirect.statusCode === 308)
        && redirect.method === request.method;
      if (!preservesTrackedMutation) request.allowGetTerminal = true;
      if (preservesTrackedMutation) {
        request.continuation = Object.freeze({
          statusCode: redirect.statusCode as 307 | 308,
          redirectedAt: redirect.timeStamp,
          expectedUrlFingerprint: redirect.redirectUrlFingerprint,
        });
      } else {
        delete request.continuation;
      }
    });
  }

  async observeCompleted(input: AutofillSaveCaptureCompletedRequest): Promise<void> {
    const eventTime = timestamp(input.timeStamp, 'timeStamp');
    this.#bumpNetworkConfirmationFrame(
      nonNegativeInteger(input.tabId, 'tabId'),
      nonNegativeInteger(input.frameId, 'frameId'),
      eventTime,
      typeof input.requestId === 'string' ? input.requestId : undefined,
    );
    return this.#mutate(async (state) => {
      let completed: Awaited<ReturnType<typeof parseCompletedRequest>>;
      try {
        completed = await parseCompletedRequest(input, this.#networkTtlMs);
      } catch {
        await this.#blockAll(state, safeDeadline(this.#time(), this.#networkTtlMs));
        return;
      }
      const request = state.requests.find((candidate) => candidate.requestId === completed.requestId);
      const phase = completed.statusCode >= 200 && completed.statusCode < 300
        ? 'succeeded' as const
        : 'failed' as const;
      if (!request) {
        const runtimeIncarnation = runtimeForTerminal(state, completed);
        if (MUTATION_METHODS.has(completed.method) && runtimeIncarnation) {
          this.#upsertOutcome(state, terminalOutcome(completed, phase, runtimeIncarnation));
        }
        return;
      }
      if (request.phase === 'failed') return;
      request.phase = terminalMatchesRequest({
        ...completed,
        completedAt: completed.timeStamp,
      }, request) ? phase : 'failed';
    });
  }

  async observeError(input: AutofillSaveCaptureErrorRequest): Promise<void> {
    const eventTime = timestamp(input.timeStamp, 'timeStamp');
    this.#bumpNetworkConfirmationFrame(
      nonNegativeInteger(input.tabId, 'tabId'),
      nonNegativeInteger(input.frameId, 'frameId'),
      eventTime,
      typeof input.requestId === 'string' ? input.requestId : undefined,
    );
    return this.#mutate(async (state) => {
      let failed: PreparedTerminal;
      try {
        failed = await parseErrorRequest(input, this.#networkTtlMs);
      } catch {
        await this.#blockAll(state, safeDeadline(this.#time(), this.#networkTtlMs));
        return;
      }
      const request = state.requests.find((candidate) => candidate.requestId === failed.requestId);
      if (!request) {
        const runtimeIncarnation = runtimeForTerminal(state, failed);
        if (MUTATION_METHODS.has(failed.method) && runtimeIncarnation) {
          this.#upsertOutcome(state, terminalOutcome(failed, 'failed', runtimeIncarnation));
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
    this.#bumpRuntimeConfirmationTab(tabId);
    this.#bumpNetworkConfirmationTab(tabId);
    this.#bumpRuntimeOperationTab(tabId);
    const confirmationFence = this.#captureConfirmationFence();
    return this.#serialize(async () => {
      let usernameFailure: unknown;
      let usernameClearFailed = false;
      try {
        await this.#usernameStages?.clearTab(tabId);
      } catch (error) {
        usernameFailure = error;
        usernameClearFailed = true;
      }
      const state = await this.#read();
      await this.#reconcileCaptureStore(state);
      const captures = state.captures.filter((capture) => capture.binding.tabId === tabId);
      for (const capture of captures) await this.#captures.discardCapture(capture.binding.captureId);
      state.captures = state.captures.filter((capture) => capture.binding.tabId !== tabId);
      state.requests = state.requests.filter((request) => request.tabId !== tabId);
      state.outcomes = state.outcomes.filter((outcome) => outcome.tabId !== tabId);
      state.activeRuntimes = state.activeRuntimes.filter((runtime) => runtime.tabId !== tabId);
      state.retiredRuntimes = state.retiredRuntimes.filter((runtime) => runtime.tabId !== tabId);
      state.admissions = state.admissions.filter((admission) => admission.tabId !== tabId);
      for (const [key, runtime] of this.#volatileRetiredRuntimes) {
        if (runtime.tabId === tabId) this.#volatileRetiredRuntimes.delete(key);
      }
      await this.#settle(state, confirmationFence);
      if (usernameClearFailed) throw usernameFailure;
    });
  }

  invalidateNetworkWindow(timeStampInput: number): Promise<void> {
    const timeStamp = timestamp(timeStampInput, 'timeStamp');
    this.#bumpGlobalConfirmation();
    return this.#mutate((state) => this.#blockAll(
      state,
      safeDeadline(timeStamp, this.#networkTtlMs),
    ));
  }

  clear(): Promise<void> {
    this.#bumpGlobalConfirmation();
    this.#bumpRuntimeOperationGlobal();
    return this.#serialize(async () => {
      let usernameFailure: unknown;
      let usernameClearFailed = false;
      try {
        await this.#usernameStages?.clear();
      } catch (error) {
        usernameFailure = error;
        usernameClearFailed = true;
      }
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
      this.#volatileRetiredRuntimes.clear();
      this.#volatileRuntimeFenceUntil = 0;
      if (usernameClearFailed) throw usernameFailure;
    });
  }

  async #retireRuntimeState(
    state: JournalState,
    activation: Pick<CanonicalRuntimeActivation, 'tabId' | 'frameId' | 'documentId'>,
    runtimeIncarnation: string,
  ): Promise<void> {
    for (const capture of [...state.captures]) {
      if (capture.phase === 'unconfirmed'
          && capture.binding.tabId === activation.tabId
          && capture.binding.frameId === activation.frameId
          && capture.binding.documentId === activation.documentId
          && capture.binding.runtimeIncarnation === runtimeIncarnation) {
        await this.#discardCapture(state, capture);
      }
    }
    state.requests = state.requests.filter((request) => !(
      request.tabId === activation.tabId
      && request.frameId === activation.frameId
      && request.documentId === activation.documentId
      && request.runtimeIncarnation === runtimeIncarnation
    ));
    state.outcomes = state.outcomes.filter((outcome) => !(
      outcome.tabId === activation.tabId
      && outcome.frameId === activation.frameId
      && outcome.documentId === activation.documentId
      && outcome.runtimeIncarnation === runtimeIncarnation
    ));
    state.admissions = state.admissions.filter((admission) => !(
      admission.tabId === activation.tabId
      && admission.frameId === activation.frameId
      && admission.documentId === activation.documentId
      && admission.runtimeIncarnation === runtimeIncarnation
    ));
    state.activeRuntimes = state.activeRuntimes.filter((runtime) => !(
      runtime.tabId === activation.tabId
      && runtime.frameId === activation.frameId
      && runtime.documentId === activation.documentId
      && runtime.runtimeIncarnation === runtimeIncarnation
    ));
  }

  #runtimeRetired(
    state: JournalState,
    runtime: Pick<ActiveRuntimeRecord, 'tabId' | 'frameId' | 'documentId' | 'runtimeIncarnation'>,
  ): boolean {
    this.#pruneVolatileRetirements();
    return this.#volatileRuntimeFenceUntil > this.#time()
      || this.#volatileRetiredRuntimes.has(runtimeRecordKey(runtime))
      || state.retiredRuntimes.some((retired) => (
      retired.tabId === runtime.tabId
      && retired.frameId === runtime.frameId
      && retired.documentId === runtime.documentId
      && retired.runtimeIncarnation === runtime.runtimeIncarnation
      ));
  }

  #rememberVolatileRetirement(
    runtime: Pick<ActiveRuntimeRecord, 'tabId' | 'frameId' | 'documentId' | 'runtimeIncarnation'>,
  ): string | undefined {
    this.#pruneVolatileRetirements();
    const key = runtimeRecordKey(runtime);
    if (this.#volatileRetiredRuntimes.has(key)) return key;
    if (this.#volatileRetiredRuntimes.size >= this.#maxRequests) {
      this.#bumpRuntimeOperationGlobal();
      this.#volatileRuntimeFenceUntil = Math.max(
        this.#volatileRuntimeFenceUntil,
        safeDeadline(this.#time(), this.#networkTtlMs),
      );
      return undefined;
    }
    this.#volatileRetiredRuntimes.set(key, Object.freeze({
      ...runtime,
      expiresAt: safeDeadline(this.#time(), this.#networkTtlMs),
    }));
    return key;
  }

  #volatileRuntimeFenceActive(): boolean {
    this.#pruneVolatileRetirements();
    return this.#volatileRuntimeFenceUntil > this.#time();
  }

  #pruneVolatileRetirements(): void {
    const now = this.#time();
    if (this.#volatileRuntimeFenceUntil <= now) this.#volatileRuntimeFenceUntil = 0;
    for (const [key, runtime] of this.#volatileRetiredRuntimes) {
      if (runtime.expiresAt <= now) this.#volatileRetiredRuntimes.delete(key);
    }
  }

  #freshAdmissionId(state: JournalState): string {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const admissionId = crypto.randomUUID();
      if (!UUID_V4.test(admissionId)) throw new Error('Save-capture admission id is invalid');
      if (!state.admissions.some((candidate) => candidate.admissionId === admissionId)) return admissionId;
    }
    throw new Error('Save-capture admission id collision');
  }

  #takeAdmission(
    state: JournalState,
    admissionId: string,
  ): PendingBeforeRequestAdmission | undefined {
    const index = state.admissions.findIndex((candidate) => candidate.admissionId === admissionId);
    return index >= 0 ? state.admissions.splice(index, 1)[0] : undefined;
  }

  async #failAdmission(
    state: JournalState,
    admission: PendingBeforeRequestAdmission,
  ): Promise<void> {
    for (const capture of [...state.captures]) {
      if (capture.phase === 'unconfirmed'
          && capture.binding.tabId === admission.tabId
          && capture.binding.frameId === admission.frameId
          && capture.binding.documentId === admission.documentId
          && capture.binding.runtimeIncarnation === admission.runtimeIncarnation
          && admission.enteredAt >= capture.binding.createdAt - this.#beforeWindowMs
          && admission.enteredAt <= capture.binding.createdAt + this.#afterWindowMs) {
        await this.#discardCapture(state, capture);
      }
    }
  }

  async #addRequest(state: JournalState, request: RequestRecord): Promise<void> {
    const existing = state.requests.find((candidate) => candidate.requestId === request.requestId);
    if (existing) {
      if (sameStartedRequest(existing, request)) return;
      if (consumeRedirectContinuation(existing, request)) return;
      await this.#blockAll(state, request.expiresAt);
      return;
    }
    if (state.requests.length >= this.#maxRequests) {
      await this.#blockAll(state, request.expiresAt);
      return;
    }
    const outcomeIndex = state.outcomes.findIndex((candidate) => (
      candidate.requestId === request.requestId
      && candidate.runtimeIncarnation === request.runtimeIncarnation
    ));
    const outcome = outcomeIndex >= 0 ? state.outcomes.splice(outcomeIndex, 1)[0] : undefined;
    if (outcome) request.phase = terminalMatchesRequest(outcome, request) ? outcome.phase : 'failed';
    state.requests.push(request);
  }

  #captureConfirmationFence(): SaveCaptureConfirmationFence {
    return Object.freeze({
      generation: this.#confirmationGeneration,
      sequence: this.#confirmationSequence,
    });
  }

  #confirmationFenceCurrent(
    fence: SaveCaptureConfirmationFence,
    binding: Pick<CaptureBinding, 'tabId' | 'frameId'>,
  ): boolean {
    if (fence.generation !== this.#confirmationGeneration
        || this.#globalConfirmationSequence > fence.sequence) return false;
    const frameKey = runtimeOperationFrameKey(binding.tabId, binding.frameId);
    return (this.#runtimeConfirmationTabSequences.get(binding.tabId) ?? 0) <= fence.sequence
      && (this.#runtimeConfirmationFrameSequences.get(frameKey) ?? 0) <= fence.sequence
      && (this.#networkConfirmationTabSequences.get(binding.tabId) ?? 0) <= fence.sequence
      && (this.#networkConfirmationFrameSequences.get(frameKey) ?? 0) <= fence.sequence;
  }

  #nextConfirmationSequence(): number {
    if (this.#confirmationSequence >= Number.MAX_SAFE_INTEGER) {
      this.#confirmationGeneration = {};
      this.#confirmationSequence = 0;
      this.#globalConfirmationSequence = 0;
      this.#runtimeConfirmationTabSequences.clear();
      this.#runtimeConfirmationFrameSequences.clear();
      this.#networkConfirmationTabSequences.clear();
      this.#networkConfirmationFrameSequences.clear();
    }
    this.#confirmationSequence += 1;
    return this.#confirmationSequence;
  }

  #bumpGlobalConfirmation(): void {
    this.#globalConfirmationSequence = this.#nextConfirmationSequence();
    this.#runtimeConfirmationTabSequences.clear();
    this.#runtimeConfirmationFrameSequences.clear();
    this.#networkConfirmationTabSequences.clear();
    this.#networkConfirmationFrameSequences.clear();
  }

  #bumpRuntimeConfirmationTab(tabId: number): void {
    if (!this.#runtimeConfirmationTabSequences.has(tabId)
        && this.#runtimeConfirmationTabSequences.size >= this.#maxRequests) {
      this.#bumpGlobalConfirmation();
    }
    this.#runtimeConfirmationTabSequences.set(tabId, this.#nextConfirmationSequence());
    this.#deleteConfirmationFrames(this.#runtimeConfirmationFrameSequences, tabId);
  }

  #bumpRuntimeConfirmationFrame(tabId: number, frameId: number): void {
    const key = runtimeOperationFrameKey(tabId, frameId);
    if (!this.#runtimeConfirmationFrameSequences.has(key)
        && this.#runtimeConfirmationFrameSequences.size >= this.#maxRequests) {
      this.#bumpGlobalConfirmation();
    }
    this.#runtimeConfirmationFrameSequences.set(
      key,
      this.#nextConfirmationSequence(),
    );
  }

  #bumpNetworkConfirmationTab(tabId: number): void {
    if (!this.#networkConfirmationTabSequences.has(tabId)
        && this.#networkConfirmationTabSequences.size >= this.#maxRequests) {
      this.#bumpGlobalConfirmation();
    }
    this.#networkConfirmationTabSequences.set(tabId, this.#nextConfirmationSequence());
    this.#deleteConfirmationFrames(this.#networkConfirmationFrameSequences, tabId);
  }

  #bumpNetworkConfirmationFrame(
    tabId: number,
    frameId: number,
    eventTime: number,
    requestId?: string,
  ): void {
    const key = runtimeOperationFrameKey(tabId, frameId);
    if (this.#networkConfirmationWindowsKnown
        && !this.#hasInFlightStageInterest(key)
        && !(requestId !== undefined && this.#networkConfirmationRequestIds.has(
          networkConfirmationRequestKey(tabId, frameId, requestId),
        ))
        && !this.#networkConfirmationWindows.get(key)?.some((window) => (
          eventTime >= window.opensAt && eventTime <= window.closesAt
        ))) return;
    if (!this.#networkConfirmationFrameSequences.has(key)
        && this.#networkConfirmationFrameSequences.size >= this.#maxRequests) {
      this.#bumpGlobalConfirmation();
    }
    this.#networkConfirmationFrameSequences.set(
      key,
      this.#nextConfirmationSequence(),
    );
  }

  #beginInFlightStageInterest(tabId: number, frameId: number): InFlightStageInterest {
    if (this.#inFlightStageInterests.size >= this.#maxRequests) {
      this.#bumpGlobalConfirmation();
      throw new Error('Save-capture in-flight stage capacity was exceeded');
    }
    const interest = Object.freeze({ frameKey: runtimeOperationFrameKey(tabId, frameId) });
    this.#inFlightStageInterests.add(interest);
    return interest;
  }

  #endInFlightStageInterest(interest: InFlightStageInterest): void {
    this.#inFlightStageInterests.delete(interest);
  }

  #hasInFlightStageInterest(frameKey: string): boolean {
    for (const interest of this.#inFlightStageInterests) {
      if (interest.frameKey === frameKey) return true;
    }
    return false;
  }

  #deleteConfirmationFrames(sequences: Map<string, number>, tabId: number): void {
    const prefix = `${tabId}\u0000`;
    for (const key of sequences.keys()) {
      if (key.startsWith(prefix)) sequences.delete(key);
    }
  }

  #captureRuntimeOperationFence(tabId: number, frameId: number): SaveCaptureRuntimeOperationFence {
    let tab = this.#runtimeOperationTabFences.get(tabId);
    if (!tab) {
      tab = {};
      this.#runtimeOperationTabFences.set(tabId, tab);
    }
    const frameKey = runtimeOperationFrameKey(tabId, frameId);
    let frame = this.#runtimeOperationFrameFences.get(frameKey);
    if (!frame) {
      frame = {};
      this.#runtimeOperationFrameFences.set(frameKey, frame);
    }
    return Object.freeze({
      global: this.#runtimeOperationGlobalFence,
      tabId,
      tab,
      frameKey,
      frame,
    });
  }

  #runtimeOperationFenceCurrent(fence: SaveCaptureRuntimeOperationFence): boolean {
    return fence.global === this.#runtimeOperationGlobalFence
      && this.#runtimeOperationTabFences.get(fence.tabId) === fence.tab
      && this.#runtimeOperationFrameFences.get(fence.frameKey) === fence.frame;
  }

  #bumpRuntimeOperationFrame(tabId: number, frameId: number): void {
    if (!this.#runtimeOperationTabFences.has(tabId)) {
      this.#runtimeOperationTabFences.set(tabId, {});
    }
    this.#runtimeOperationFrameFences.set(runtimeOperationFrameKey(tabId, frameId), {});
  }

  #bumpRuntimeOperationTab(tabId: number): void {
    this.#runtimeOperationTabFences.delete(tabId);
    const prefix = `${tabId}\u0000`;
    for (const key of this.#runtimeOperationFrameFences.keys()) {
      if (key.startsWith(prefix)) this.#runtimeOperationFrameFences.delete(key);
    }
  }

  #bumpRuntimeOperationGlobal(): void {
    this.#runtimeOperationGlobalFence = {};
    this.#runtimeOperationTabFences.clear();
    this.#runtimeOperationFrameFences.clear();
  }

  #mutate(mutation: (state: JournalState) => void | Promise<void>): Promise<void> {
    const confirmationFence = this.#captureConfirmationFence();
    return this.#serialize(async () => {
      const state = await this.#read();
      await this.#reconcileCaptureStore(state);
      await mutation(state);
      await this.#settle(state, confirmationFence);
    });
  }

  async #settle(state: JournalState, confirmationFence: SaveCaptureConfirmationFence): Promise<void> {
    await this.#evaluate(state, confirmationFence);
    await this.#write(state);
    await this.#notifyConfirmed(state);
    await this.#write(state);
    this.#reschedule(state);
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#tail.then(operation, operation);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async #read(): Promise<JournalState> {
    const now = this.#time();
    let raw: unknown;
    try {
      raw = await this.#store.get<unknown>(this.#storageKey);
    } catch (error) {
      this.#bumpRuntimeOperationGlobal();
      throw error;
    }
    if (raw === undefined) {
      this.#bumpRuntimeOperationGlobal();
      const state = emptyJournal(this.#highWaterRevision);
      this.#refreshNetworkConfirmationScope(state);
      return state;
    }
    const parsed = parseJournal(raw, now, this.#maxRequests);
    if (!parsed) {
      this.#bumpRuntimeOperationGlobal();
      const state = {
        ...emptyJournal(this.#highWaterRevision),
        blockedUntil: safeDeadline(now, this.#networkTtlMs),
        runtimeFenceUntil: safeDeadline(now, this.#networkTtlMs),
      };
      this.#refreshNetworkConfirmationScope(state);
      return state;
    }
    if (parsed.runtimeFenceUntil > now) this.#bumpRuntimeOperationGlobal();
    this.#highWaterRevision = Math.max(this.#highWaterRevision, parsed.revision);
    this.#refreshNetworkConfirmationScope(parsed);
    return parsed;
  }

  async #write(state: JournalState): Promise<void> {
    this.#refreshNetworkConfirmationScope(state);
    const revision = Math.max(state.revision, this.#highWaterRevision);
    if (!Number.isSafeInteger(revision) || revision >= Number.MAX_SAFE_INTEGER) {
      throw new Error('Save-capture journal revision is exhausted');
    }
    const envelope: StoredJournal = Object.freeze({
      schemaVersion: AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION,
      revision: revision + 1,
      blockedUntil: state.blockedUntil,
      runtimeFenceUntil: state.runtimeFenceUntil,
      captures: Object.freeze(state.captures.map(freezeCaptureRecord)),
      requests: Object.freeze(state.requests.map(freezeRequestRecord)),
      outcomes: Object.freeze(state.outcomes.map((outcome) => Object.freeze({ ...outcome }))),
      activeRuntimes: Object.freeze(state.activeRuntimes.map((runtime) => Object.freeze({ ...runtime }))),
      retiredRuntimes: Object.freeze(state.retiredRuntimes.map((runtime) => Object.freeze({ ...runtime }))),
      admissions: Object.freeze(state.admissions.map((admission) => Object.freeze({ ...admission }))),
    });
    if (utf8Size(this.#storageKey, envelope) > this.#maxJournalBytes) {
      this.#bumpRuntimeOperationGlobal();
      const captures = [...state.captures];
      const blockedUntil = safeDeadline(this.#time(), this.#networkTtlMs);
      state.blockedUntil = Math.max(state.blockedUntil, blockedUntil);
      state.runtimeFenceUntil = Math.max(state.runtimeFenceUntil, blockedUntil);
      state.captures = [];
      state.requests = [];
      state.outcomes = [];
      state.activeRuntimes = [];
      state.retiredRuntimes = [];
      state.admissions = [];
      this.#refreshNetworkConfirmationScope(state);
      const blockedEnvelope: StoredJournal = Object.freeze({
        schemaVersion: AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION,
        revision: revision + 1,
        blockedUntil: state.blockedUntil,
        runtimeFenceUntil: state.runtimeFenceUntil,
        captures: Object.freeze([]),
        requests: Object.freeze([]),
        outcomes: Object.freeze([]),
        activeRuntimes: Object.freeze([]),
        retiredRuntimes: Object.freeze([]),
        admissions: Object.freeze([]),
      });
      await this.#store.set(this.#storageKey, blockedEnvelope);
      state.revision = blockedEnvelope.revision;
      this.#highWaterRevision = blockedEnvelope.revision;
      for (const capture of captures) {
        await this.#captures.discardCapture(capture.binding.captureId).catch(() => false);
      }
      throw new Error('Save-capture journal capacity was exceeded');
    }
    await this.#store.set(this.#storageKey, envelope);
    state.revision = envelope.revision;
    this.#highWaterRevision = envelope.revision;
  }

  #refreshNetworkConfirmationScope(state: JournalState): void {
    this.#networkConfirmationWindows.clear();
    this.#networkConfirmationRequestIds.clear();
    const captures = state.captures.filter((capture) => capture.phase === 'unconfirmed');
    for (const capture of captures) {
      const key = runtimeOperationFrameKey(capture.binding.tabId, capture.binding.frameId);
      const windows = this.#networkConfirmationWindows.get(key) ?? [];
      this.#networkConfirmationWindows.set(key, Object.freeze([
        ...windows,
        Object.freeze({
          opensAt: Math.max(0, capture.binding.createdAt - this.#beforeWindowMs),
          closesAt: safeDeadline(capture.binding.createdAt, this.#afterWindowMs),
        }),
      ]));
    }
    for (const request of state.requests) {
      if (captures.some((capture) => this.#requestMatches(capture, request))) {
        this.#networkConfirmationRequestIds.add(networkConfirmationRequestKey(
          request.tabId,
          request.frameId,
          request.requestId,
        ));
      }
    }
    this.#networkConfirmationWindowsKnown = true;
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
      else if (captureState !== capture.phase) {
        await this.#captures.discardCapture(capture.binding.captureId);
        state.captures.splice(index, 1);
      }
    }
  }

  async #evaluate(
    state: JournalState,
    confirmationFence = this.#captureConfirmationFence(),
  ): Promise<void> {
    const now = this.#time();
    for (const retired of state.retiredRuntimes.filter((runtime) => runtime.cleanupPending)) {
      try {
        await this.#retireRuntimeState(state, retired, retired.runtimeIncarnation);
        await this.#clearUsernameRuntime(
          retired.tabId,
          retired.frameId,
          retired.documentId,
          retired.runtimeIncarnation,
        );
        await this.#usernameStages?.clearRuntime(
          retired.tabId,
          retired.frameId,
          retired.documentId,
          retired.runtimeIncarnation,
        );
        retired.cleanupPending = false;
        this.#volatileRetiredRuntimes.delete(runtimeRecordKey(retired));
      } catch {
        // The durable tombstone remains authoritative and the alarm retries bounded cleanup.
      }
    }
    const expiredAdmissions = state.admissions.filter((admission) => admission.expiresAt <= now);
    state.admissions = state.admissions.filter((admission) => admission.expiresAt > now);
    for (const admission of expiredAdmissions) await this.#failAdmission(state, admission);
    state.retiredRuntimes = state.retiredRuntimes.filter((runtime) => (
      runtime.cleanupPending || runtime.expiresAt > now
    ));
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
    if (state.runtimeFenceUntil !== 0 && state.runtimeFenceUntil <= now) {
      state.runtimeFenceUntil = 0;
    }

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
      if (this.#runtimeRetired(state, capture.binding)) {
        await this.#discardCapture(state, capture);
        continue;
      }
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
      const admissions = state.admissions.filter((admission) => this.#admissionMayMatch(capture, admission));
      if (admissions.some((admission) => admission.status === 'failed')) {
        await this.#discardCapture(state, capture);
        continue;
      }
      if (admissions.length > 0) continue;
      await this.#confirmCapture(state, capture, confirmationFence);
      if (state.blockedUntil > now) return;
    }
  }

  #requestMatches(capture: CaptureRecord, request: RequestRecord): boolean {
    const binding = capture.binding;
    if (request.tabId !== binding.tabId
        || request.frameId !== binding.frameId
        || request.documentId !== binding.documentId
        || request.runtimeIncarnation !== binding.runtimeIncarnation
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

  #admissionMayMatch(
    capture: CaptureRecord,
    admission: PendingBeforeRequestAdmission,
  ): boolean {
    return admission.tabId === capture.binding.tabId
      && admission.frameId === capture.binding.frameId
      && admission.documentId === capture.binding.documentId
      && admission.runtimeIncarnation === capture.binding.runtimeIncarnation
      && admission.enteredAt >= capture.binding.createdAt - this.#beforeWindowMs
      && admission.enteredAt <= capture.binding.createdAt + this.#afterWindowMs;
  }

  async #confirmCapture(
    state: JournalState,
    capture: CaptureRecord,
    confirmationFence: SaveCaptureConfirmationFence,
  ): Promise<void> {
    const metadata = capture.metadata;
    if (!metadata) return;
    let key: SymmetricKey | undefined;
    try {
      this.#assertCurrent(metadata);
      key = await this.#loadUserKey(metadata);
      this.#assertCurrent(metadata);
      if (!key) return;
      const confirmed = await this.#captures.confirmUnconfirmed(metadata, key, () => {
        if (!this.#confirmationFenceCurrent(confirmationFence, capture.binding)) {
          throw new Error('Save-capture confirmation fence changed');
        }
      });
      key = undefined;
      if (!this.#confirmationFenceCurrent(confirmationFence, capture.binding)) {
        throw new Error('Save-capture confirmation fence changed');
      }
      this.#assertCurrent(metadata);
      if (confirmed || await this.#captures.captureState(capture.binding.captureId) === 'confirmed') {
        capture.phase = 'confirmed';
      }
    } catch {
      zeroOwnedUserKey(key);
      try {
        if (await this.#captures.captureState(capture.binding.captureId) === 'confirmed') {
          try {
            await this.#discardCapture(state, capture);
          } catch {
            this.#markConfirmationBlocked(state);
          }
        }
      } catch {
        this.#markConfirmationBlocked(state);
      }
    }
  }

  #markConfirmationBlocked(state: JournalState): void {
    state.blockedUntil = Math.max(
      state.blockedUntil,
      safeDeadline(this.#time(), this.#networkTtlMs),
    );
    state.requests = [];
    state.outcomes = [];
    state.admissions = [];
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
    const existing = state.outcomes.find((candidate) => (
      candidate.requestId === outcome.requestId
      && candidate.runtimeIncarnation === outcome.runtimeIncarnation
    ));
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
    state.admissions = [];
    for (const capture of [...state.captures]) await this.#discardCapture(state, capture);
  }

  #reschedule(state: JournalState): void {
    const now = this.#time();
    const candidates: number[] = [];
    if (state.blockedUntil > now) candidates.push(state.blockedUntil);
    if (state.runtimeFenceUntil > now) candidates.push(state.runtimeFenceUntil);
    for (const capture of state.captures) {
      candidates.push(capture.binding.expiresAt);
      if (capture.phase === 'confirmed') candidates.push(safeDeadline(now, CONFIRMED_NOTIFICATION_RETRY_MS));
      else {
        const closesAt = safeDeadline(capture.binding.createdAt, this.#afterWindowMs);
        if (closesAt > now) candidates.push(closesAt);
        else {
          const matchingRequests = state.requests.filter((request) => this.#requestMatches(capture, request));
          if (matchingRequests.length === 1 && matchingRequests[0]?.phase === 'succeeded') {
            candidates.push(safeDeadline(now, CONFIRMED_NOTIFICATION_RETRY_MS));
          }
        }
      }
    }
    for (const request of state.requests) candidates.push(request.expiresAt);
    for (const outcome of state.outcomes) candidates.push(outcome.expiresAt);
    for (const retired of state.retiredRuntimes) {
      if (retired.cleanupPending) candidates.push(safeDeadline(now, CONFIRMED_NOTIFICATION_RETRY_MS));
      else candidates.push(retired.expiresAt);
    }
    for (const admission of state.admissions) candidates.push(admission.expiresAt);
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
      runtimeIncarnation: metadata.runtimeIncarnation,
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
    && binding.runtimeIncarnation === metadata.runtimeIncarnation
    && binding.sourceOrigin === metadata.origin
    && binding.sourceOrigin === source.documentOrigin
    && binding.sourceSite === source.documentSite
    && binding.sourceUrlFingerprint === source.documentUrlFingerprint
    && binding.createdAt === metadata.createdAt
    && binding.expiresAt === metadata.expiresAt;
}

function canonicalRuntimeActivation(
  value: AutofillSaveCaptureRuntimeActivation,
): CanonicalRuntimeActivation {
  if (!isPlainRecord(value)) throw new TypeError('Save-capture runtime activation is invalid');
  const hasPrevious = Object.hasOwn(value, 'previousRuntimeIncarnation');
  const record = strictRecord(value, hasPrevious
    ? ['tabId', 'frameId', 'documentId', 'frameUrl', 'runtimeIncarnation', 'previousRuntimeIncarnation']
    : ['tabId', 'frameId', 'documentId', 'frameUrl', 'runtimeIncarnation'], 'runtime activation');
  const frameUrl = canonicalRequestUrl(dataValue(record, 'frameUrl'), 'frameUrl');
  const runtimeIncarnation = uuid(dataValue(record, 'runtimeIncarnation'), 'runtimeIncarnation');
  const previousRuntimeIncarnation = hasPrevious
    ? uuid(dataValue(record, 'previousRuntimeIncarnation'), 'previousRuntimeIncarnation')
    : undefined;
  if (previousRuntimeIncarnation === runtimeIncarnation) {
    throw new TypeError('Save-capture replacement runtime must change');
  }
  return {
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(record, 'frameId'), 'frameId'),
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
    frameUrl,
    runtimeIncarnation,
    ...(previousRuntimeIncarnation ? { previousRuntimeIncarnation } : {}),
  };
}

function canonicalBeforeRequestAdmission(
  value: AutofillSaveCaptureBeforeRequestAdmission,
  ttlMs: number,
): CanonicalBeforeRequestAdmission {
  if (!isPlainRecord(value)) throw new TypeError('Save-capture before-request admission is invalid');
  const optional = [
    ...(Object.hasOwn(value, 'documentId') ? ['documentId'] : []),
    ...(Object.hasOwn(value, 'sourceDocumentUrl') ? ['sourceDocumentUrl'] : []),
  ];
  const record = strictRecord(
    value,
    ['requestId', 'tabId', 'frameId', 'timeStamp', ...optional],
    'before-request admission',
  );
  const enteredAt = timestamp(dataValue(record, 'timeStamp'), 'timeStamp');
  const documentId = Object.hasOwn(record, 'documentId')
    ? opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH)
    : undefined;
  const sourceDocumentUrl = Object.hasOwn(record, 'sourceDocumentUrl')
    ? canonicalRequestUrl(dataValue(record, 'sourceDocumentUrl'), 'sourceDocumentUrl')
    : undefined;
  return Object.freeze({
    requestId: opaqueId(dataValue(record, 'requestId'), 'requestId', MAX_REQUEST_ID_LENGTH),
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(record, 'frameId'), 'frameId'),
    ...(documentId ? { documentId } : {}),
    ...(sourceDocumentUrl ? { sourceDocumentUrl } : {}),
    enteredAt,
    expiresAt: safeDeadline(enteredAt, ttlMs),
  });
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

async function parseBeforeRequest(value: unknown, ttlMs: number): Promise<PreparedBeforeRequest> {
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
    allowGetTerminal: false,
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
    statusCode: statusCode as number,
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
  runtimeIncarnation: string,
): TerminalOutcome {
  return {
    requestId: input.requestId,
    tabId: input.tabId,
    frameId: input.frameId,
    documentId: input.documentId,
    runtimeIncarnation,
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

function terminalMatchesRequest(
  outcome: Pick<
    TerminalOutcome,
    'requestId' | 'tabId' | 'frameId' | 'documentId' | 'urlFingerprint' | 'method' | 'type' | 'completedAt'
  >,
  request: RequestRecord,
): boolean {
  return terminalIdentityMatches(outcome, request)
    && request.continuation === undefined
    && outcome.urlFingerprint === request.currentUrlFingerprint
    && outcome.type === request.type
    && (outcome.method === request.method
      || (request.allowGetTerminal && outcome.method === 'GET'))
    && outcome.completedAt >= request.startedAt;
}

function sameStartedRequest(left: RequestRecord, right: RequestRecord): boolean {
  return left.requestId === right.requestId
    && left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId
    && left.runtimeIncarnation === right.runtimeIncarnation
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
    && left.runtimeIncarnation === right.runtimeIncarnation
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
    && left.runtimeIncarnation === right.runtimeIncarnation
    && left.sourceUrlFingerprint === right.sourceUrlFingerprint;
}

function consumeRedirectContinuation(existing: RequestRecord, next: RequestRecord): boolean {
  const continuation = existing.continuation;
  if (!continuation
      || existing.phase !== 'redirected'
      || existing.requestId !== next.requestId
      || existing.tabId !== next.tabId
      || existing.frameId !== next.frameId
      || existing.documentId !== next.documentId
      || existing.runtimeIncarnation !== next.runtimeIncarnation
      || existing.documentOrigin !== next.documentOrigin
      || existing.documentSite !== next.documentSite
      || existing.documentUrlFingerprint !== next.documentUrlFingerprint
      || existing.method !== next.method
      || existing.type !== next.type
      || next.initialUrlFingerprint !== continuation.expectedUrlFingerprint
      || next.initialUrlFingerprint !== existing.currentUrlFingerprint
      || next.startedAt < continuation.redirectedAt) return false;
  existing.currentOrigin = next.initialOrigin;
  existing.currentSite = next.initialSite;
  existing.currentUrlFingerprint = next.initialUrlFingerprint;
  existing.phase = 'started';
  delete existing.continuation;
  return true;
}

function uniqueRuntimeForPreparedRequest(
  state: JournalState,
  request: PreparedBeforeRequest,
): ActiveRuntimeRecord | undefined {
  const active = state.activeRuntimes.filter((runtime) => (
    runtime.tabId === request.tabId
    && runtime.frameId === request.frameId
    && runtime.documentId === request.documentId
    && runtime.documentUrlFingerprint === request.documentUrlFingerprint
  ));
  if (active.length === 1) return active[0];
  const incarnations = new Set(state.captures.filter((capture) => (
    capture.binding.tabId === request.tabId
    && capture.binding.frameId === request.frameId
    && capture.binding.documentId === request.documentId
    && capture.binding.sourceUrlFingerprint === request.documentUrlFingerprint
  )).map((capture) => capture.binding.runtimeIncarnation));
  if (incarnations.size !== 1) return undefined;
  const runtimeIncarnation = incarnations.values().next().value as string;
  return {
    tabId: request.tabId,
    frameId: request.frameId,
    documentId: request.documentId,
    runtimeIncarnation,
    documentUrlFingerprint: request.documentUrlFingerprint,
    activatedAt: request.startedAt,
  };
}

function runtimeForTerminal(
  state: JournalState,
  terminal: Pick<PreparedTerminal, 'requestId' | 'tabId' | 'frameId' | 'documentId' | 'type'>,
): string | undefined {
  const matches = new Set(state.admissions.filter((admission) => (
    admission.requestId === terminal.requestId
    && admission.tabId === terminal.tabId
    && admission.frameId === terminal.frameId
    && (terminal.type !== 'xmlhttprequest' || admission.documentId === terminal.documentId)
  )).map((admission) => admission.runtimeIncarnation));
  return matches.size === 1 ? matches.values().next().value : undefined;
}

function sameRuntimeDocument(
  left: Pick<ActiveRuntimeRecord, 'tabId' | 'frameId' | 'documentId'>,
  right: Pick<CanonicalRuntimeActivation, 'tabId' | 'frameId' | 'documentId'>,
): boolean {
  return left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId;
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
    'schemaVersion', 'revision', 'blockedUntil', 'runtimeFenceUntil', 'captures', 'requests', 'outcomes',
    'activeRuntimes', 'retiredRuntimes', 'admissions',
  ])) return undefined;
  if (dataValue(value, 'schemaVersion') !== AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION) return undefined;
  const revision = dataValue(value, 'revision');
  const blockedUntil = dataValue(value, 'blockedUntil');
  const runtimeFenceUntil = dataValue(value, 'runtimeFenceUntil');
  const rawCaptures = dataValue(value, 'captures');
  const rawRequests = dataValue(value, 'requests');
  const rawOutcomes = dataValue(value, 'outcomes');
  const rawActiveRuntimes = dataValue(value, 'activeRuntimes');
  const rawRetiredRuntimes = dataValue(value, 'retiredRuntimes');
  const rawAdmissions = dataValue(value, 'admissions');
  if (!Number.isSafeInteger(revision) || (revision as number) < 0
      || !Number.isSafeInteger(blockedUntil) || (blockedUntil as number) < 0
      || !Number.isSafeInteger(runtimeFenceUntil) || (runtimeFenceUntil as number) < 0
      || !Array.isArray(rawCaptures) || !denseArray(rawCaptures) || rawCaptures.length > capacity
      || !Array.isArray(rawRequests) || !denseArray(rawRequests) || rawRequests.length > capacity
      || !Array.isArray(rawOutcomes) || !denseArray(rawOutcomes) || rawOutcomes.length > capacity
      || !Array.isArray(rawActiveRuntimes) || !denseArray(rawActiveRuntimes) || rawActiveRuntimes.length > capacity
      || !Array.isArray(rawRetiredRuntimes) || !denseArray(rawRetiredRuntimes) || rawRetiredRuntimes.length > capacity
      || !Array.isArray(rawAdmissions) || !denseArray(rawAdmissions) || rawAdmissions.length > capacity) return undefined;
  try {
    const captures = rawCaptures.map(parseCaptureRecord);
    const requests = rawRequests.map(parseStoredRequest);
    const outcomes = rawOutcomes.map(parseStoredOutcome);
    const activeRuntimes = rawActiveRuntimes.map(parseActiveRuntime);
    const retiredRuntimes = rawRetiredRuntimes.map(parseRetiredRuntime);
    const admissions = rawAdmissions.map(parseAdmission);
    if (new Set(captures.map((capture) => capture.binding.captureId)).size !== captures.length
        || new Set(requests.map((request) => request.requestId)).size !== requests.length
        || new Set(outcomes.map((outcome) => `${outcome.runtimeIncarnation}\u0000${outcome.requestId}`)).size !== outcomes.length
        || new Set(activeRuntimes.map((runtime) => JSON.stringify([runtime.tabId, runtime.frameId]))).size !== activeRuntimes.length
        || new Set(retiredRuntimes.map(runtimeRecordKey)).size !== retiredRuntimes.length
        || new Set(admissions.map((admission) => admission.admissionId)).size !== admissions.length) return undefined;
    return {
      revision: revision as number,
      blockedUntil: blockedUntil as number,
      runtimeFenceUntil: runtimeFenceUntil as number,
      captures: captures.filter((capture) => capture.binding.expiresAt > now),
      requests: requests.filter((request) => request.expiresAt > now),
      outcomes: outcomes.filter((outcome) => outcome.expiresAt > now),
      activeRuntimes,
      retiredRuntimes: retiredRuntimes.filter((runtime) => runtime.cleanupPending || runtime.expiresAt > now),
      admissions,
      dirty: captures.some((capture) => capture.binding.expiresAt <= now)
        || requests.some((request) => request.expiresAt <= now)
        || outcomes.some((outcome) => outcome.expiresAt <= now)
        || retiredRuntimes.some((runtime) => !runtime.cleanupPending && runtime.expiresAt <= now)
        || admissions.some((admission) => admission.expiresAt <= now),
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
    'runtimeIncarnation', 'sourceUrlFingerprint', 'createdAt', 'expiresAt',
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
    runtimeIncarnation: uuid(dataValue(record, 'runtimeIncarnation'), 'runtimeIncarnation'),
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
  const baseKeys = [
    'requestId', 'tabId', 'frameId', 'documentId',
    'runtimeIncarnation',
    'documentOrigin', 'documentSite', 'documentUrlFingerprint',
    'initialOrigin', 'initialSite', 'initialUrlFingerprint',
    'currentOrigin', 'currentSite', 'currentUrlFingerprint',
    'method', 'type', 'startedAt', 'expiresAt', 'phase', 'redirectCount', 'allowGetTerminal',
  ] as const;
  const hasContinuation = isPlainRecord(value) && Object.hasOwn(value, 'continuation');
  const record = strictRecord(
    value,
    hasContinuation ? [...baseKeys, 'continuation'] : baseKeys,
    'request record',
  );
  const startedAt = timestamp(dataValue(record, 'startedAt'), 'startedAt');
  const expiresAt = timestamp(dataValue(record, 'expiresAt'), 'expiresAt');
  const redirectCount = dataValue(record, 'redirectCount');
  const allowGetTerminal = dataValue(record, 'allowGetTerminal');
  const phase = dataValue(record, 'phase');
  const type = dataValue(record, 'type');
  if (expiresAt <= startedAt
      || !Number.isSafeInteger(redirectCount) || (redirectCount as number) < 0 || (redirectCount as number) > MAX_REDIRECTS
      || typeof allowGetTerminal !== 'boolean'
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
  const continuation = parseStoredContinuation(dataValue(record, 'continuation'));
  if (continuation && (phase !== 'redirected'
      || continuation.redirectedAt < startedAt
      || continuation.redirectedAt >= expiresAt)) {
    throw new TypeError('Request continuation is invalid');
  }
  return {
    requestId: opaqueId(dataValue(record, 'requestId'), 'requestId', MAX_REQUEST_ID_LENGTH),
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId,
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
    runtimeIncarnation: uuid(dataValue(record, 'runtimeIncarnation'), 'runtimeIncarnation'),
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
    allowGetTerminal,
    ...(continuation ? { continuation } : {}),
  };
}

function parseStoredOutcome(value: unknown): TerminalOutcome {
  const record = strictRecord(value, [
    'requestId', 'tabId', 'frameId', 'documentId', 'urlFingerprint',
    'runtimeIncarnation', 'method', 'type', 'completedAt', 'expiresAt', 'phase',
  ], 'terminal outcome');
  const phase = dataValue(record, 'phase');
  const completedAt = timestamp(dataValue(record, 'completedAt'), 'completedAt');
  const expiresAt = timestamp(dataValue(record, 'expiresAt'), 'expiresAt');
  if ((phase !== 'succeeded' && phase !== 'failed') || expiresAt <= completedAt) {
    throw new TypeError('Terminal outcome is invalid');
  }
  return {
    ...terminalIdentityWithoutUrl(record),
    runtimeIncarnation: uuid(dataValue(record, 'runtimeIncarnation'), 'runtimeIncarnation'),
    ...terminalTransport(record),
    urlFingerprint: fingerprint(dataValue(record, 'urlFingerprint')),
    completedAt,
    expiresAt,
    phase,
  };
}

function parseStoredContinuation(
  value: unknown,
): RequestRecord['continuation'] {
  if (value === undefined) return undefined;
  const record = strictRecord(
    value,
    ['statusCode', 'redirectedAt', 'expectedUrlFingerprint'],
    'redirect continuation',
  );
  const statusCode = dataValue(record, 'statusCode');
  if (statusCode !== 307 && statusCode !== 308) {
    throw new TypeError('Redirect continuation status is invalid');
  }
  return Object.freeze({
    statusCode,
    redirectedAt: timestamp(dataValue(record, 'redirectedAt'), 'redirectedAt'),
    expectedUrlFingerprint: fingerprint(dataValue(record, 'expectedUrlFingerprint')),
  });
}

function parseActiveRuntime(value: unknown): ActiveRuntimeRecord {
  const record = strictRecord(value, [
    'tabId', 'frameId', 'documentId', 'runtimeIncarnation',
    'documentUrlFingerprint', 'activatedAt',
  ], 'active runtime');
  return Object.freeze({
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(record, 'frameId'), 'frameId'),
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
    runtimeIncarnation: uuid(dataValue(record, 'runtimeIncarnation'), 'runtimeIncarnation'),
    documentUrlFingerprint: fingerprint(dataValue(record, 'documentUrlFingerprint')),
    activatedAt: timestamp(dataValue(record, 'activatedAt'), 'activatedAt'),
  });
}

function parseRetiredRuntime(value: unknown): RetiredRuntimeRecord {
  const record = strictRecord(value, [
    'tabId', 'frameId', 'documentId', 'runtimeIncarnation',
    'retiredAt', 'expiresAt', 'cleanupPending',
  ], 'retired runtime');
  const retiredAt = timestamp(dataValue(record, 'retiredAt'), 'retiredAt');
  const expiresAt = timestamp(dataValue(record, 'expiresAt'), 'expiresAt');
  const cleanupPending = dataValue(record, 'cleanupPending');
  if (expiresAt <= retiredAt || expiresAt - retiredAt > 5 * 60_000) {
    throw new TypeError('Retired runtime expiry is invalid');
  }
  if (typeof cleanupPending !== 'boolean') {
    throw new TypeError('Retired runtime cleanup state is invalid');
  }
  return {
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(record, 'frameId'), 'frameId'),
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
    runtimeIncarnation: uuid(dataValue(record, 'runtimeIncarnation'), 'runtimeIncarnation'),
    retiredAt,
    expiresAt,
    cleanupPending,
  };
}

function parseAdmission(value: unknown): PendingBeforeRequestAdmission {
  const record = strictRecord(value, [
    'admissionId', 'requestId', 'tabId', 'frameId', 'documentId',
    'runtimeIncarnation', 'status', 'enteredAt', 'expiresAt',
  ], 'before-request admission');
  const enteredAt = timestamp(dataValue(record, 'enteredAt'), 'enteredAt');
  const expiresAt = timestamp(dataValue(record, 'expiresAt'), 'expiresAt');
  if (expiresAt <= enteredAt || expiresAt - enteredAt > 5 * 60_000) {
    throw new TypeError('Before-request admission expiry is invalid');
  }
  const status = dataValue(record, 'status');
  if (status !== 'pending' && status !== 'failed') {
    throw new TypeError('Before-request admission status is invalid');
  }
  return {
    admissionId: uuid(dataValue(record, 'admissionId'), 'admissionId'),
    requestId: opaqueId(dataValue(record, 'requestId'), 'requestId', MAX_REQUEST_ID_LENGTH),
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(record, 'frameId'), 'frameId'),
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
    runtimeIncarnation: uuid(dataValue(record, 'runtimeIncarnation'), 'runtimeIncarnation'),
    status,
    enteredAt,
    expiresAt,
  };
}

function runtimeRecordKey(
  runtime: Pick<ActiveRuntimeRecord, 'tabId' | 'frameId' | 'documentId' | 'runtimeIncarnation'>,
): string {
  return JSON.stringify([
    runtime.tabId,
    runtime.frameId,
    runtime.documentId,
    runtime.runtimeIncarnation,
  ]);
}

function runtimeOperationFrameKey(tabId: number, frameId: number): string {
  return `${tabId}\u0000${frameId}`;
}

function networkConfirmationRequestKey(tabId: number, frameId: number, requestId: string): string {
  return `${runtimeOperationFrameKey(tabId, frameId)}\u0000${requestId}`;
}

function freezeCaptureRecord(record: CaptureRecord): CaptureRecord {
  return Object.freeze({
    binding: Object.freeze({ ...record.binding }),
    submission: Object.freeze({ ...record.submission }),
    phase: record.phase,
  });
}

function freezeRequestRecord(record: RequestRecord): RequestRecord {
  return Object.freeze({
    ...record,
    ...(record.continuation
      ? { continuation: Object.freeze({ ...record.continuation }) }
      : {}),
  });
}

function emptyJournal(revision: number): JournalState {
  return {
    revision,
    blockedUntil: 0,
    runtimeFenceUntil: 0,
    captures: [],
    requests: [],
    outcomes: [],
    activeRuntimes: [],
    retiredRuntimes: [],
    admissions: [],
  };
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
