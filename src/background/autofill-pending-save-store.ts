import type { SymmetricKey } from '../core/crypto/keys.js';
import type { KeyValueStore } from '../platform/store.js';

export const AUTOFILL_PENDING_SAVE_STORAGE_KEY = 'autofillPendingSaves';
export const AUTOFILL_PENDING_SAVE_SCHEMA_VERSION = 3 as const;
export const DEFAULT_AUTOFILL_PENDING_SAVE_TTL_MS = 2 * 60_000;
export const MAX_AUTOFILL_PENDING_SAVE_TTL_MS = 10 * 60_000;
export const DEFAULT_AUTOFILL_PENDING_SAVE_CLAIM_LEASE_MS = 5_000;
export const MAX_AUTOFILL_PENDING_SAVE_CLAIM_LEASE_MS = 30_000;
export const DEFAULT_AUTOFILL_PENDING_SAVE_CAPACITY = 32;
export const MAX_AUTOFILL_PENDING_SAVE_CAPACITY = 64;
/** A deliberately small share of Chrome's storage.session quota; other security state owns most. */
export const AUTOFILL_PENDING_SAVE_ENVELOPE_MAX_UTF8_BYTES = 1024 * 1024;

const MAX_STORAGE_KEY_LENGTH = 256;
const MAX_OPAQUE_ID_LENGTH = 4_096;
const MAX_URL_LENGTH = 16 * 1_024;
const MAX_ACCOUNT_IDENTITY_LENGTH = 4_096;
const MAX_USERNAME_LENGTH = 4_096;
const MAX_PASSWORD_LENGTH = 65_536;
const MAX_DISPLAY_LENGTH = 4_096;
const MAX_CIPHERTEXT_BYTES = 128 * 1_024;
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BITS = 128;
const SHA256_BYTES = 32;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HKDF_SALT = new TextEncoder().encode('miyu/autofill-pending-save/hkdf-salt/v1');
const AES_INFO = new TextEncoder().encode('miyu/autofill-pending-save/aes-gcm/v1');
const DECISION_INFO = new TextEncoder().encode('miyu/autofill-pending-save/decision-hmac/v1');
const AAD_DOMAIN = 'miyu/autofill-pending-save/aad/v3';
const DECISION_AAD_DOMAIN = 'miyu/autofill-pending-save/decision-aad/v3';
const DECISION_DOMAIN = 'miyu/autofill-pending-save/decision/v3';

export interface AutofillPendingSaveSecurityBinding {
  readonly sessionGeneration: number;
  readonly sessionBindingId: string;
  readonly serverGeneration: number;
  readonly accountGeneration: number;
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly policyGeneration: number;
  readonly enterprisePolicyGeneration: number;
  readonly enterprisePolicyRawGeneration: string;
}

export interface AutofillPendingSaveInput extends AutofillPendingSaveSecurityBinding {
  readonly tabId: number;
  readonly frameId: number;
  readonly sourceDocumentId: string;
  readonly sourceUrl: string;
  readonly origin: string;
}

export interface AutofillPendingSaveDocumentContext extends AutofillPendingSaveSecurityBinding {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly frameUrl: string;
  readonly origin: string;
}

export interface AutofillPendingSaveCredentials {
  readonly username?: string;
  readonly password: string;
}

export interface AutofillUnconfirmedSaveMetadata extends AutofillPendingSaveInput {
  readonly captureId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export type AutofillPendingSaveCaptureState = 'unconfirmed' | 'confirmed';

export type AutofillPendingSaveDecision =
  | { readonly action: 'none' }
  | { readonly action: 'save'; readonly suggestedName: string }
  | { readonly action: 'update'; readonly cipherId: string; readonly name: string }
  | { readonly action: 'addUri'; readonly cipherId: string; readonly name: string };

export type AutofillPendingSavePublicPrompt =
  | { readonly action: 'none' }
  | { readonly action: 'retry'; readonly retryAfterMs: number }
  | { readonly action: 'save'; readonly promptId: string; readonly suggestedName: string }
  | { readonly action: 'update'; readonly promptId: string; readonly name: string }
  | { readonly action: 'addUri'; readonly promptId: string; readonly name: string };

export interface TakenAutofillPendingSave {
  readonly credentials: AutofillPendingSaveCredentials;
  readonly sourceUrl: string;
  readonly decision: Exclude<AutofillPendingSaveDecision, { readonly action: 'none' }>;
}

export type AutofillPendingSaveEvaluator = (
  credentials: AutofillPendingSaveCredentials,
  sourceUrl: string,
) => AutofillPendingSaveDecision | PromiseLike<AutofillPendingSaveDecision>;

export interface AutofillPendingSaveStoreOptions {
  readonly store: Pick<KeyValueStore, 'get' | 'set'>;
  readonly storageKey?: string;
  readonly now?: () => number;
  readonly ttlMs?: number;
  readonly claimLeaseMs?: number;
  readonly maxEntries?: number;
  readonly createId?: () => string;
  readonly randomBytes?: (length: number) => Uint8Array;
}

export type AutofillPendingSaveStoreErrorCode =
  | 'invalid_configuration'
  | 'invalid_input'
  | 'id_generation'
  | 'revision_exhausted'
  | 'storage_capacity';

export class AutofillPendingSaveStoreError extends Error {
  constructor(readonly code: AutofillPendingSaveStoreErrorCode, message: string) {
    super(message);
    this.name = 'AutofillPendingSaveStoreError';
  }
}

interface PendingEntryBase extends AutofillPendingSaveSecurityBinding {
  readonly entryId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly sourceDocumentId: string;
  readonly sourceUrl: string;
  readonly origin: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly confirmation: AutofillPendingSaveCaptureState;
  readonly iv: string;
  readonly ciphertext: string;
}

interface UnconfirmedPendingEntry extends PendingEntryBase {
  readonly confirmation: 'unconfirmed';
  readonly state: 'unconfirmed';
}

interface UnclaimedPendingEntry extends PendingEntryBase {
  readonly confirmation: 'confirmed';
  readonly state: 'pending';
}

interface ClaimedPendingEntry extends PendingEntryBase {
  readonly confirmation: 'confirmed';
  readonly state: 'claimed';
  readonly promptId: string;
  readonly claimDocumentId: string;
  readonly claimedAt: number;
  readonly claimExpiresAt: number;
  readonly decisionIv: string;
  readonly decisionCiphertext: string;
  readonly decisionTag: string;
}

type StoredPendingEntry = UnconfirmedPendingEntry | UnclaimedPendingEntry | ClaimedPendingEntry;

interface PendingSaveEnvelope {
  readonly schemaVersion: typeof AUTOFILL_PENDING_SAVE_SCHEMA_VERSION;
  readonly revision: number;
  readonly entries: readonly StoredPendingEntry[];
}

interface ParsedEnvelope {
  readonly revision: number;
  readonly entries: StoredPendingEntry[];
  readonly dirty: boolean;
}

interface DerivedKeys {
  readonly encryption: CryptoKey;
  readonly decision: CryptoKey;
}

interface OperationQueue {
  tail: Promise<void>;
  highWaterRevision: number;
}

const OPERATION_QUEUES = new Map<string, OperationQueue>();

/**
 * Holds short-lived captured credentials across MV3 worker and same-origin document navigation.
 * Credentials and claim decisions are encrypted under a domain-separated derivative of an owned
 * UserKey. Claims are document-bound leases; only take or dismiss removes a live prompt.
 */
export class AutofillPendingSaveStore {
  readonly #store: AutofillPendingSaveStoreOptions['store'];
  readonly #storageKey: string;
  readonly #now: () => number;
  readonly #ttlMs: number;
  readonly #claimLeaseMs: number;
  readonly #maxEntries: number;
  readonly #createId: () => string;
  readonly #randomBytes: (length: number) => Uint8Array;
  readonly #queue: OperationQueue;

  constructor(options: AutofillPendingSaveStoreOptions) {
    if (!options?.store || typeof options.store.get !== 'function' || typeof options.store.set !== 'function') {
      throw configurationError('A storage.session store with get and set is required.');
    }
    this.#store = options.store;
    this.#storageKey = storageKey(options.storageKey ?? AUTOFILL_PENDING_SAVE_STORAGE_KEY);
    this.#now = options.now ?? Date.now;
    this.#ttlMs = boundedPositiveInteger(
      options.ttlMs ?? DEFAULT_AUTOFILL_PENDING_SAVE_TTL_MS,
      MAX_AUTOFILL_PENDING_SAVE_TTL_MS,
      'ttlMs',
    );
    this.#claimLeaseMs = boundedPositiveInteger(
      options.claimLeaseMs ?? DEFAULT_AUTOFILL_PENDING_SAVE_CLAIM_LEASE_MS,
      Math.min(MAX_AUTOFILL_PENDING_SAVE_CLAIM_LEASE_MS, this.#ttlMs),
      'claimLeaseMs',
    );
    this.#maxEntries = boundedPositiveInteger(
      options.maxEntries ?? DEFAULT_AUTOFILL_PENDING_SAVE_CAPACITY,
      MAX_AUTOFILL_PENDING_SAVE_CAPACITY,
      'maxEntries',
    );
    this.#createId = options.createId ?? (() => crypto.randomUUID());
    this.#randomBytes = options.randomBytes ?? ((length) => crypto.getRandomValues(new Uint8Array(length)));
    this.#queue = operationQueue(this.#storageKey);
  }

  /** Persist one encrypted capture. The owned UserKey is zeroed before this promise settles. */
  async put(
    input: AutofillPendingSaveInput,
    credentials: AutofillPendingSaveCredentials,
    ownedUserKey: SymmetricKey,
  ): Promise<void> {
    await this.#put(input, credentials, ownedUserKey, 'confirmed');
  }

  /** Quarantine one encrypted capture until browser-owned network evidence confirms submission. */
  putUnconfirmed(
    input: AutofillPendingSaveInput,
    credentials: AutofillPendingSaveCredentials,
    ownedUserKey: SymmetricKey,
  ): Promise<AutofillUnconfirmedSaveMetadata> {
    return this.#put(input, credentials, ownedUserKey, 'unconfirmed');
  }

  async #put(
    input: AutofillPendingSaveInput,
    credentials: AutofillPendingSaveCredentials,
    ownedUserKey: SymmetricKey,
    confirmation: AutofillPendingSaveCaptureState,
  ): Promise<AutofillUnconfirmedSaveMetadata> {
    return withOwnedUserKey(ownedUserKey, async (keys) => {
      const canonicalInput = canonicalizeInput(input);
      const canonicalCredentials = canonicalizeCredentials(credentials);
      return this.#serialize(async () => {
        const now = this.#currentTime();
        const current = await this.#read(now);
        const entryId = this.#freshId(current.entries, 'entry');
        const expiresAt = safeDeadline(now, this.#ttlMs, 'pending save expiry');
        const baseWithoutCiphertext = {
          entryId,
          tabId: canonicalInput.tabId,
          frameId: canonicalInput.frameId,
          sourceDocumentId: canonicalInput.sourceDocumentId,
          sourceUrl: canonicalInput.sourceUrl,
          origin: canonicalInput.origin,
          sessionGeneration: canonicalInput.sessionGeneration,
          sessionBindingId: canonicalInput.sessionBindingId,
          serverGeneration: canonicalInput.serverGeneration,
          accountGeneration: canonicalInput.accountGeneration,
          serverUrl: canonicalInput.serverUrl,
          accountIdentity: canonicalInput.accountIdentity,
          policyGeneration: canonicalInput.policyGeneration,
          enterprisePolicyGeneration: canonicalInput.enterprisePolicyGeneration,
          enterprisePolicyRawGeneration: canonicalInput.enterprisePolicyRawGeneration,
          createdAt: now,
          expiresAt,
          confirmation,
        };
        const encrypted = await encryptCredentials(
          baseWithoutCiphertext,
          canonicalCredentials,
          keys.encryption,
          this.#freshRandomBytes(AES_GCM_IV_BYTES),
        );
        const entry: UnconfirmedPendingEntry | UnclaimedPendingEntry = confirmation === 'unconfirmed'
          ? { ...baseWithoutCiphertext, ...encrypted, confirmation, state: 'unconfirmed' }
          : { ...baseWithoutCiphertext, ...encrypted, confirmation, state: 'pending' };
        const retained = current.entries.filter((candidate) => (
          !sameCaptureSlot(candidate, canonicalInput)
        ));
        retained.push(entry);
        retained.sort(compareEntriesOldestFirst);
        while (retained.length > this.#maxEntries) retained.shift();
        while (!this.#fitsNextEnvelope(current.revision, retained) && retained.length > 1) {
          retained.shift();
        }
        if (!this.#fitsNextEnvelope(current.revision, retained)) {
          throw new AutofillPendingSaveStoreError(
            'storage_capacity',
            'The pending-save storage envelope is too large.',
          );
        }
        await this.#write(current.revision, retained);
        return unconfirmedMetadata(entry);
      });
    });
  }

  /** Promote one exact quarantined capture by re-encrypting it under authenticated confirmed AAD. */
  async confirmUnconfirmed(
    metadataInput: AutofillUnconfirmedSaveMetadata,
    ownedUserKey: SymmetricKey,
  ): Promise<boolean> {
    return withOwnedUserKey(ownedUserKey, async (keys) => {
      const expected = canonicalizeUnconfirmedMetadata(metadataInput);
      return this.#serialize(async () => {
        const current = await this.#read(this.#currentTime());
        const entry = current.entries.find((candidate) => candidate.entryId === expected.captureId);
        if (!entry || !sameUnconfirmedMetadata(entry, expected)) {
          if (current.dirty) await this.#write(current.revision, current.entries);
          return false;
        }
        if (entry.confirmation === 'confirmed') {
          if (current.dirty) await this.#write(current.revision, current.entries);
          return true;
        }
        const credentials = await decryptCredentials(entry, keys.encryption);
        if (!credentials) {
          await this.#write(
            current.revision,
            current.entries.filter((candidate) => candidate.entryId !== entry.entryId),
          );
          return false;
        }
        const confirmedBase = credentialAadBase(entry, 'confirmed');
        const encrypted = await encryptCredentials(
          confirmedBase,
          credentials,
          keys.encryption,
          this.#freshRandomBytes(AES_GCM_IV_BYTES),
        );
        const confirmed: UnclaimedPendingEntry = {
          ...confirmedBase,
          ...encrypted,
          confirmation: 'confirmed',
          state: 'pending',
        };
        const entries = current.entries.map((candidate) => (
          candidate.entryId === entry.entryId ? confirmed : candidate
        ));
        if (!this.#fitsNextEnvelope(current.revision, entries)) {
          throw new AutofillPendingSaveStoreError(
            'storage_capacity',
            'The confirmed pending-save envelope is too large.',
          );
        }
        await this.#write(current.revision, entries);
        return true;
      });
    });
  }

  /** Delete one opaque capture in any phase so negative network evidence always wins. */
  async discardCapture(captureIdInput: string): Promise<boolean> {
    const captureId = uuid(captureIdInput, 'captureId');
    return this.#serialize(async () => {
      const current = await this.#read(this.#currentTime());
      const entries = current.entries.filter((entry) => entry.entryId !== captureId);
      if (current.dirty || entries.length !== current.entries.length) {
        await this.#write(current.revision, entries);
      }
      return entries.length !== current.entries.length;
    });
  }

  async captureState(captureIdInput: string): Promise<AutofillPendingSaveCaptureState | undefined> {
    const captureId = uuid(captureIdInput, 'captureId');
    return this.#serialize(async () => {
      const current = await this.#read(this.#currentTime());
      const entry = current.entries.find((candidate) => candidate.entryId === captureId);
      if (current.dirty) await this.#write(current.revision, current.entries);
      return entry?.confirmation;
    });
  }

  async captureMetadata(captureIdInput: string): Promise<AutofillUnconfirmedSaveMetadata | undefined> {
    const captureId = uuid(captureIdInput, 'captureId');
    return this.#serialize(async () => {
      const current = await this.#read(this.#currentTime());
      const entry = current.entries.find((candidate) => candidate.entryId === captureId);
      if (current.dirty) await this.#write(current.revision, current.entries);
      return entry ? unconfirmedMetadata(entry) : undefined;
    });
  }

  async listUnconfirmed(): Promise<readonly AutofillUnconfirmedSaveMetadata[]> {
    return this.#serialize(async () => {
      const current = await this.#read(this.#currentTime());
      if (current.dirty) await this.#write(current.revision, current.entries);
      return Object.freeze(current.entries
        .filter((entry): entry is UnconfirmedPendingEntry => entry.state === 'unconfirmed')
        .map(unconfirmedMetadata));
    });
  }

  /**
   * Claim the newest matching capture for this document. A same-document call is idempotent while
   * its lease is live; another document receives only a retry delay until that lease can be reclaimed.
   */
  async claim(
    context: AutofillPendingSaveDocumentContext,
    ownedUserKey: SymmetricKey,
    evaluate: AutofillPendingSaveEvaluator,
  ): Promise<AutofillPendingSavePublicPrompt> {
    return withOwnedUserKey(ownedUserKey, async (keys) => {
      const canonicalContext = canonicalizeDocumentContext(context);
      assertEvaluator(evaluate);
      return this.#serialize(async () => {
        const now = this.#currentTime();
        const current = await this.#read(now, true);
        let entries = current.entries;
        let dirty = current.dirty;

        const withoutStaleBindings = entries.filter((entry) => (
          !sameBrowserOrigin(entry, canonicalContext)
          || sameSecurityBinding(entry, canonicalContext)
        ));
        if (withoutStaleBindings.length !== entries.length) {
          entries = withoutStaleBindings;
          dirty = true;
        }

        const matching = entries.filter((entry) => sameClaimScope(entry, canonicalContext));
        const idempotent = [...matching].reverse().find((entry): entry is ClaimedPendingEntry => (
          entry.state === 'claimed' && entry.claimDocumentId === canonicalContext.documentId
        ));
        if (idempotent) {
          const decision = await decryptDecision(idempotent, keys.encryption);
          if (!decision) {
            entries = entries.filter((entry) => entry.entryId !== idempotent.entryId);
            await this.#write(current.revision, entries);
            return { action: 'none' };
          }
          const expectedTag = await decisionTag(keys.decision, idempotent, decision);
          const authentic = constantTimeBase64Equal(expectedTag, idempotent.decisionTag);
          if (!authentic) {
            entries = entries.filter((entry) => entry.entryId !== idempotent.entryId);
            await this.#write(current.revision, entries);
            return { action: 'none' };
          }
          if (dirty) await this.#write(current.revision, entries);
          return publicPrompt(idempotent.promptId, decision);
        }

        const available = [...matching].reverse().find((entry) => entry.state === 'pending');
        if (!available) {
          const retryAt = matching.reduce<number | undefined>((soonest, entry) => (
            entry.state !== 'claimed'
              ? soonest
              : Math.min(soonest ?? entry.claimExpiresAt, entry.claimExpiresAt)
          ), undefined);
          if (dirty) await this.#write(current.revision, entries);
          return retryAt === undefined
            ? { action: 'none' }
            : { action: 'retry', retryAfterMs: Math.max(1, retryAt - now) };
        }

        const evaluated = await this.#evaluateEntry(available, keys, evaluate);
        if (!evaluated || evaluated.action === 'none') {
          entries = entries.filter((entry) => entry.entryId !== available.entryId);
          await this.#write(current.revision, entries);
          return { action: 'none' };
        }
        const promptId = this.#freshId(entries, 'prompt');
        const claimExpiresAt = Math.min(
          available.expiresAt,
          safeDeadline(now, this.#claimLeaseMs, 'pending save claim expiry'),
        );
        if (claimExpiresAt <= now) {
          entries = entries.filter((entry) => entry.entryId !== available.entryId);
          await this.#write(current.revision, entries);
          return { action: 'none' };
        }
        const claimMetadata = {
          ...available,
          state: 'claimed' as const,
          promptId,
          claimDocumentId: canonicalContext.documentId,
          claimedAt: now,
          claimExpiresAt,
        };
        const encryptedDecision = await encryptDecision(
          keys.encryption,
          claimMetadata,
          evaluated,
          this.#freshRandomBytes(AES_GCM_IV_BYTES),
        );
        const claimed: ClaimedPendingEntry = {
          ...claimMetadata,
          ...encryptedDecision,
          decisionTag: await decisionTag(keys.decision, claimMetadata, evaluated),
        };
        entries = entries.map((entry) => entry.entryId === available.entryId ? claimed : entry);
        if (!this.#fitsNextEnvelope(current.revision, entries)) {
          throw new AutofillPendingSaveStoreError(
            'storage_capacity',
            'The claimed pending-save envelope is too large.',
          );
        }
        await this.#write(current.revision, entries);
        return publicPrompt(promptId, evaluated);
      });
    });
  }

  /**
   * Decrypt and consume one exact document claim. The encrypted entry is durably removed before
   * credentials and its authenticated decision are returned, preventing a second save on replay.
   */
  async take(
    promptId: string,
    context: AutofillPendingSaveDocumentContext,
    ownedUserKey: SymmetricKey,
  ): Promise<TakenAutofillPendingSave | undefined> {
    return withOwnedUserKey(ownedUserKey, async (keys) => {
      const canonicalPromptId = uuid(promptId, 'promptId');
      const canonicalContext = canonicalizeDocumentContext(context);
      return this.#serialize(async () => {
        const now = this.#currentTime();
        const current = await this.#read(now);
        const entry = current.entries.find((candidate): candidate is ClaimedPendingEntry => (
          candidate.state === 'claimed'
          && candidate.promptId === canonicalPromptId
          && candidate.claimDocumentId === canonicalContext.documentId
          && sameClaimScope(candidate, canonicalContext)
        ));
        if (!entry) {
          if (current.dirty) await this.#write(current.revision, current.entries);
          return undefined;
        }

        const decision = await decryptDecision(entry, keys.encryption);
        const expectedTag = decision
          ? await decisionTag(keys.decision, entry, decision)
          : undefined;
        const authenticDecision = decision && expectedTag
          ? constantTimeBase64Equal(expectedTag, entry.decisionTag)
          : false;
        const credentials = authenticDecision
          ? await decryptCredentials(entry, keys.encryption)
          : undefined;

        await this.#write(
          current.revision,
          current.entries.filter((candidate) => candidate.entryId !== entry.entryId),
        );
        if (!credentials || !decision || !authenticDecision) return undefined;
        return Object.freeze({ credentials, sourceUrl: entry.sourceUrl, decision });
      });
    });
  }

  /** Remove one live prompt only when its complete claimant document binding still matches. */
  async dismiss(
    promptId: string,
    context: AutofillPendingSaveDocumentContext,
  ): Promise<boolean> {
    const canonicalPromptId = uuid(promptId, 'promptId');
    const canonicalContext = canonicalizeDocumentContext(context);
    return this.#serialize(async () => {
      const current = await this.#read(this.#currentTime());
      const entry = current.entries.find((candidate): candidate is ClaimedPendingEntry => (
        candidate.state === 'claimed'
        && candidate.promptId === canonicalPromptId
        && candidate.claimDocumentId === canonicalContext.documentId
        && sameClaimScope(candidate, canonicalContext)
      ));
      if (!entry) {
        if (current.dirty) await this.#write(current.revision, current.entries);
        return false;
      }
      await this.#write(
        current.revision,
        current.entries.filter((candidate) => candidate.entryId !== entry.entryId),
      );
      return true;
    });
  }

  async clearTab(tabId: number): Promise<void> {
    const canonicalTabId = nonNegativeInteger(tabId, 'tabId');
    await this.#serialize(async () => {
      const current = await this.#read(this.#currentTime());
      const entries = current.entries.filter((entry) => entry.tabId !== canonicalTabId);
      if (current.dirty || entries.length !== current.entries.length) {
        await this.#write(current.revision, entries);
      }
    });
  }

  async clear(): Promise<void> {
    await this.#serialize(async () => {
      const current = await this.#read(this.#currentTime());
      await this.#write(current.revision, []);
    });
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#queue.tail.then(operation, operation);
    this.#queue.tail = result.then(() => undefined, () => undefined);
    return result;
  }

  #currentTime(): number {
    const now = this.#now();
    if (!isTimestamp(now)) throw configurationError('now must return a non-negative safe integer.');
    return now;
  }

  #freshRandomBytes(length: number): Uint8Array {
    const bytes = this.#randomBytes(length);
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== length) {
      if (bytes instanceof Uint8Array) bytes.fill(0);
      throw configurationError('randomBytes returned an invalid byte array.');
    }
    return bytes;
  }

  #freshId(entries: readonly StoredPendingEntry[], kind: 'entry' | 'prompt'): string {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const candidate = this.#createId();
      if (typeof candidate !== 'string' || !UUID_V4.test(candidate)) {
        throw new AutofillPendingSaveStoreError(
          'id_generation',
          'Pending-save identifiers must be lowercase UUID v4 values.',
        );
      }
      const collision = entries.some((entry) => (
        entry.entryId === candidate
        || (entry.state === 'claimed' && entry.promptId === candidate)
      ));
      if (!collision) return candidate;
    }
    throw new AutofillPendingSaveStoreError('id_generation', `${kind} identifier collision.`);
  }

  async #read(now: number, reclaimExpiredClaims = false): Promise<ParsedEnvelope> {
    const raw = await this.#store.get<unknown>(this.#storageKey);
    if (raw === undefined) {
      return { revision: this.#queue.highWaterRevision, entries: [], dirty: false };
    }
    const extractedRevision = extractRevision(raw);
    if (extractedRevision !== undefined) {
      this.#queue.highWaterRevision = Math.max(this.#queue.highWaterRevision, extractedRevision);
    }
    const parsed = parseEnvelope(raw, now, this.#maxEntries, this.#storageKey, reclaimExpiredClaims);
    if (!parsed) {
      return { revision: this.#queue.highWaterRevision, entries: [], dirty: true };
    }
    this.#queue.highWaterRevision = Math.max(this.#queue.highWaterRevision, parsed.revision);
    return parsed;
  }

  async #write(revision: number, entries: readonly StoredPendingEntry[]): Promise<void> {
    const base = Math.max(revision, this.#queue.highWaterRevision);
    if (!Number.isSafeInteger(base) || base < 0 || base >= Number.MAX_SAFE_INTEGER) {
      throw new AutofillPendingSaveStoreError(
        'revision_exhausted',
        'Pending-save storage revision is exhausted.',
      );
    }
    const envelope: PendingSaveEnvelope = {
      schemaVersion: AUTOFILL_PENDING_SAVE_SCHEMA_VERSION,
      revision: base + 1,
      entries,
    };
    if (!hasBoundedEnvelopeSize(this.#storageKey, envelope)) {
      throw new AutofillPendingSaveStoreError(
        'storage_capacity',
        'The pending-save storage envelope is too large.',
      );
    }
    await this.#store.set(this.#storageKey, envelope);
    this.#queue.highWaterRevision = envelope.revision;
  }

  #fitsNextEnvelope(revision: number, entries: readonly StoredPendingEntry[]): boolean {
    const nextRevision = Math.max(revision, this.#queue.highWaterRevision) + 1;
    return Number.isSafeInteger(nextRevision) && hasBoundedEnvelopeSize(this.#storageKey, {
      schemaVersion: AUTOFILL_PENDING_SAVE_SCHEMA_VERSION,
      revision: nextRevision,
      entries,
    });
  }

  async #evaluateEntry(
    entry: StoredPendingEntry,
    keys: DerivedKeys,
    evaluate: AutofillPendingSaveEvaluator,
  ): Promise<AutofillPendingSaveDecision | undefined> {
    const credentials = await decryptCredentials(entry, keys.encryption);
    if (!credentials) return undefined;
    const rawDecision = await evaluate(credentials, entry.sourceUrl);
    try {
      return canonicalizeDecision(rawDecision);
    } catch {
      return undefined;
    }
  }
}

function operationQueue(storageKeyValue: string): OperationQueue {
  const existing = OPERATION_QUEUES.get(storageKeyValue);
  if (existing) return existing;
  const queue: OperationQueue = { tail: Promise.resolve(), highWaterRevision: 0 };
  OPERATION_QUEUES.set(storageKeyValue, queue);
  return queue;
}

async function withOwnedUserKey<Result>(
  ownedUserKey: SymmetricKey,
  operation: (keys: DerivedKeys) => Promise<Result>,
): Promise<Result> {
  let raw: Uint8Array | undefined;
  let encryptionBytes: Uint8Array | undefined;
  let decisionBytes: Uint8Array | undefined;
  let encryption: CryptoKey | undefined;
  let decision: CryptoKey | undefined;
  try {
    if (
      !ownedUserKey
      || !(ownedUserKey.encKey instanceof Uint8Array)
      || !(ownedUserKey.macKey instanceof Uint8Array)
      || ownedUserKey.encKey.byteLength !== 32
      || ownedUserKey.macKey.byteLength !== 32
    ) throw new AutofillPendingSaveStoreError('invalid_input', 'ownedUserKey is invalid.');
    raw = new Uint8Array(64);
    raw.set(ownedUserKey.encKey, 0);
    raw.set(ownedUserKey.macKey, 32);
    const root = await crypto.subtle.importKey('raw', raw as BufferSource, 'HKDF', false, ['deriveBits']);
    encryptionBytes = new Uint8Array(await crypto.subtle.deriveBits({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: HKDF_SALT as BufferSource,
      info: AES_INFO as BufferSource,
    }, root, 256));
    decisionBytes = new Uint8Array(await crypto.subtle.deriveBits({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: HKDF_SALT as BufferSource,
      info: DECISION_INFO as BufferSource,
    }, root, 256));
    encryption = await crypto.subtle.importKey(
      'raw', encryptionBytes as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
    );
    decision = await crypto.subtle.importKey(
      'raw', decisionBytes as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
  } finally {
    raw?.fill(0);
    encryptionBytes?.fill(0);
    decisionBytes?.fill(0);
    zeroOwnedUserKey(ownedUserKey);
  }
  if (!encryption || !decision) {
    throw new AutofillPendingSaveStoreError('invalid_input', 'Unable to derive pending-save keys.');
  }
  return operation({ encryption, decision });
}

function zeroOwnedUserKey(key: SymmetricKey | undefined): void {
  try { if (key?.encKey instanceof Uint8Array) key.encKey.fill(0); } catch { /* best effort */ }
  try { if (key?.macKey instanceof Uint8Array) key.macKey.fill(0); } catch { /* best effort */ }
}

async function encryptCredentials(
  base: Omit<PendingEntryBase, 'iv' | 'ciphertext'>,
  credentials: AutofillPendingSaveCredentials,
  encryptionKey: CryptoKey,
  iv: Uint8Array,
): Promise<Pick<PendingEntryBase, 'iv' | 'ciphertext'>> {
  let plaintext: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  try {
    plaintext = new TextEncoder().encode(JSON.stringify(credentials));
    aad = encodeAad(base);
    ciphertext = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: AES_GCM_TAG_BITS,
    }, encryptionKey, plaintext as BufferSource));
    if (ciphertext.byteLength > MAX_CIPHERTEXT_BYTES) {
      throw new AutofillPendingSaveStoreError(
        'storage_capacity',
        'Encrypted pending credentials exceed the supported size.',
      );
    }
    return Object.freeze({
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(ciphertext),
    });
  } finally {
    iv.fill(0);
    plaintext?.fill(0);
    aad?.fill(0);
    ciphertext?.fill(0);
  }
}

async function decryptCredentials(
  entry: StoredPendingEntry,
  encryptionKey: CryptoKey,
): Promise<AutofillPendingSaveCredentials | undefined> {
  let iv: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    iv = canonicalBase64Bytes(entry.iv, AES_GCM_IV_BYTES, AES_GCM_IV_BYTES);
    ciphertext = canonicalBase64Bytes(entry.ciphertext, 16, MAX_CIPHERTEXT_BYTES);
    aad = encodeAad(entry);
    plaintext = new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: AES_GCM_TAG_BITS,
    }, encryptionKey, ciphertext as BufferSource));
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    return canonicalizeCredentials(JSON.parse(decoded) as unknown);
  } catch {
    return undefined;
  } finally {
    iv?.fill(0);
    ciphertext?.fill(0);
    aad?.fill(0);
    plaintext?.fill(0);
  }
}

async function encryptDecision(
  encryptionKey: CryptoKey,
  claim: Omit<ClaimedPendingEntry, 'decisionIv' | 'decisionCiphertext' | 'decisionTag'>,
  decision: Exclude<AutofillPendingSaveDecision, { readonly action: 'none' }>,
  decisionIv: Uint8Array,
): Promise<Pick<ClaimedPendingEntry, 'decisionIv' | 'decisionCiphertext'>> {
  let plaintext: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  try {
    plaintext = new TextEncoder().encode(JSON.stringify(decision));
    aad = encodeDecisionAad(claim);
    ciphertext = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-GCM',
      iv: decisionIv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: AES_GCM_TAG_BITS,
    }, encryptionKey, plaintext as BufferSource));
    if (ciphertext.byteLength > MAX_CIPHERTEXT_BYTES) {
      throw new AutofillPendingSaveStoreError(
        'storage_capacity',
        'Encrypted pending-save decision exceeds the supported size.',
      );
    }
    return Object.freeze({
      decisionIv: bytesToBase64(decisionIv),
      decisionCiphertext: bytesToBase64(ciphertext),
    });
  } finally {
    decisionIv.fill(0);
    plaintext?.fill(0);
    aad?.fill(0);
    ciphertext?.fill(0);
  }
}

async function decryptDecision(
  entry: ClaimedPendingEntry,
  encryptionKey: CryptoKey,
): Promise<Exclude<AutofillPendingSaveDecision, { readonly action: 'none' }> | undefined> {
  let iv: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    iv = canonicalBase64Bytes(entry.decisionIv, AES_GCM_IV_BYTES, AES_GCM_IV_BYTES);
    ciphertext = canonicalBase64Bytes(entry.decisionCiphertext, 16, MAX_CIPHERTEXT_BYTES);
    aad = encodeDecisionAad(entry);
    plaintext = new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: AES_GCM_TAG_BITS,
    }, encryptionKey, ciphertext as BufferSource));
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    const decision = canonicalizeDecision(JSON.parse(decoded) as unknown);
    return decision.action === 'none' ? undefined : decision;
  } catch {
    return undefined;
  } finally {
    iv?.fill(0);
    ciphertext?.fill(0);
    aad?.fill(0);
    plaintext?.fill(0);
  }
}

function encodeAad(entry: Omit<PendingEntryBase, 'iv' | 'ciphertext'>): Uint8Array {
  return new TextEncoder().encode(JSON.stringify([
    AAD_DOMAIN,
    AUTOFILL_PENDING_SAVE_SCHEMA_VERSION,
    entry.entryId,
    entry.tabId,
    entry.frameId,
    entry.sourceDocumentId,
    entry.origin,
    entry.sourceUrl,
    entry.sessionBindingId,
    entry.sessionGeneration,
    entry.serverGeneration,
    entry.accountGeneration,
    entry.serverUrl,
    entry.accountIdentity,
    entry.policyGeneration,
    entry.enterprisePolicyGeneration,
    entry.enterprisePolicyRawGeneration,
    entry.createdAt,
    entry.expiresAt,
    entry.confirmation,
  ]));
}

function encodeDecisionAad(
  claim: Omit<ClaimedPendingEntry, 'decisionIv' | 'decisionCiphertext' | 'decisionTag'>,
): Uint8Array {
  return new TextEncoder().encode(JSON.stringify([
    DECISION_AAD_DOMAIN,
    AUTOFILL_PENDING_SAVE_SCHEMA_VERSION,
    claim.entryId,
    claim.tabId,
    claim.frameId,
    claim.sourceDocumentId,
    claim.origin,
    claim.sourceUrl,
    claim.sessionBindingId,
    claim.sessionGeneration,
    claim.serverGeneration,
    claim.accountGeneration,
    claim.serverUrl,
    claim.accountIdentity,
    claim.policyGeneration,
    claim.enterprisePolicyGeneration,
    claim.enterprisePolicyRawGeneration,
    claim.createdAt,
    claim.expiresAt,
    claim.confirmation,
    claim.iv,
    claim.ciphertext,
    claim.state,
    claim.promptId,
    claim.claimDocumentId,
    claim.claimedAt,
    claim.claimExpiresAt,
  ]));
}

async function decisionTag(
  key: CryptoKey,
  claim: Pick<
    ClaimedPendingEntry,
    | 'entryId'
    | 'promptId'
    | 'claimDocumentId'
    | 'sourceUrl'
    | 'origin'
    | 'enterprisePolicyGeneration'
    | 'enterprisePolicyRawGeneration'
  >,
  decision: Exclude<AutofillPendingSaveDecision, { readonly action: 'none' }>,
): Promise<string> {
  const payload = new TextEncoder().encode(JSON.stringify([
    DECISION_DOMAIN,
    claim.entryId,
    claim.promptId,
    claim.claimDocumentId,
    claim.origin,
    claim.sourceUrl,
    claim.enterprisePolicyGeneration,
    claim.enterprisePolicyRawGeneration,
    decision.action,
    decision.action === 'save' ? null : decision.cipherId,
    decision.action === 'save' ? decision.suggestedName : decision.name,
  ]));
  let tag: Uint8Array | undefined;
  try {
    tag = new Uint8Array(await crypto.subtle.sign('HMAC', key, payload as BufferSource));
    return bytesToBase64(tag);
  } finally {
    payload.fill(0);
    tag?.fill(0);
  }
}

function publicPrompt(
  promptId: string,
  decision: Exclude<AutofillPendingSaveDecision, { readonly action: 'none' }>,
): AutofillPendingSavePublicPrompt {
  if (decision.action === 'save') {
    return Object.freeze({ action: 'save', promptId, suggestedName: decision.suggestedName });
  }
  return Object.freeze({ action: decision.action, promptId, name: decision.name });
}

function parseEnvelope(
  value: unknown,
  now: number,
  configuredCapacity: number,
  storageKeyValue: string,
  reclaimExpiredClaims: boolean,
): ParsedEnvelope | undefined {
  if (!isPlainRecord(value) || !hasExactDataKeys(value, ['schemaVersion', 'revision', 'entries'])) {
    return undefined;
  }
  const schemaVersion = dataValue(value, 'schemaVersion');
  const revision = dataValue(value, 'revision');
  const rawEntries = dataValue(value, 'entries');
  if (
    schemaVersion !== AUTOFILL_PENDING_SAVE_SCHEMA_VERSION
    || !isRevision(revision)
    || !Array.isArray(rawEntries)
    || rawEntries.length > MAX_AUTOFILL_PENDING_SAVE_CAPACITY
    || !hasDenseArrayShape(rawEntries)
  ) return undefined;

  const entries: StoredPendingEntry[] = [];
  const entryIds = new Set<string>();
  const promptIds = new Set<string>();
  let dirty = false;
  for (const rawEntry of rawEntries) {
    const parsed = parseEntry(rawEntry, now);
    if (!parsed) return undefined;
    if (entryIds.has(parsed.entryId)) return undefined;
    entryIds.add(parsed.entryId);
    if (parsed.state === 'claimed') {
      if (promptIds.has(parsed.promptId)) return undefined;
      promptIds.add(parsed.promptId);
    }
    if (parsed.expiresAt <= now) {
      dirty = true;
      continue;
    }
    if (reclaimExpiredClaims && parsed.state === 'claimed' && parsed.claimExpiresAt <= now) {
      entries.push(toUnclaimed(parsed));
      dirty = true;
      continue;
    }
    entries.push(parsed);
  }
  for (const promptId of promptIds) {
    if (entryIds.has(promptId)) return undefined;
  }
  entries.sort(compareEntriesOldestFirst);
  if (entries.length > configuredCapacity) {
    entries.splice(0, entries.length - configuredCapacity);
    dirty = true;
  }
  const envelope: PendingSaveEnvelope = {
    schemaVersion: AUTOFILL_PENDING_SAVE_SCHEMA_VERSION,
    revision,
    entries: rawEntries as unknown as StoredPendingEntry[],
  };
  if (!hasBoundedEnvelopeSize(storageKeyValue, envelope)) return undefined;
  return { revision, entries, dirty };
}

function parseEntry(value: unknown, now: number): StoredPendingEntry | undefined {
  if (!isPlainRecord(value)) return undefined;
  const state = dataValue(value, 'state');
  const confirmation = dataValue(value, 'confirmation');
  const baseKeys = [
    'entryId', 'tabId', 'frameId', 'sourceDocumentId', 'sourceUrl', 'origin',
    'sessionGeneration', 'sessionBindingId', 'serverGeneration', 'accountGeneration',
    'serverUrl', 'accountIdentity', 'policyGeneration', 'enterprisePolicyGeneration',
    'enterprisePolicyRawGeneration', 'createdAt', 'expiresAt', 'confirmation', 'iv', 'ciphertext', 'state',
  ] as const;
  const expected = state === 'claimed'
    ? [
        ...baseKeys, 'promptId', 'claimDocumentId', 'claimedAt', 'claimExpiresAt',
        'decisionIv', 'decisionCiphertext', 'decisionTag',
      ]
    : baseKeys;
  if (
    (state !== 'unconfirmed' && state !== 'pending' && state !== 'claimed')
    || (state === 'unconfirmed' ? confirmation !== 'unconfirmed' : confirmation !== 'confirmed')
    || !hasExactDataKeys(value, expected)
  ) {
    return undefined;
  }
  let input: AutofillPendingSaveInput;
  try {
    input = canonicalizeInput({
      tabId: dataValue(value, 'tabId'),
      frameId: dataValue(value, 'frameId'),
      sourceDocumentId: dataValue(value, 'sourceDocumentId'),
      sourceUrl: dataValue(value, 'sourceUrl'),
      origin: dataValue(value, 'origin'),
      sessionGeneration: dataValue(value, 'sessionGeneration'),
      sessionBindingId: dataValue(value, 'sessionBindingId'),
      serverGeneration: dataValue(value, 'serverGeneration'),
      accountGeneration: dataValue(value, 'accountGeneration'),
      serverUrl: dataValue(value, 'serverUrl'),
      accountIdentity: dataValue(value, 'accountIdentity'),
      policyGeneration: dataValue(value, 'policyGeneration'),
      enterprisePolicyGeneration: dataValue(value, 'enterprisePolicyGeneration'),
      enterprisePolicyRawGeneration: dataValue(value, 'enterprisePolicyRawGeneration'),
    });
  } catch {
    return undefined;
  }
  const entryId = dataValue(value, 'entryId');
  const createdAt = dataValue(value, 'createdAt');
  const expiresAt = dataValue(value, 'expiresAt');
  const iv = dataValue(value, 'iv');
  const ciphertext = dataValue(value, 'ciphertext');
  if (
    typeof entryId !== 'string'
    || !UUID_V4.test(entryId)
    || !isTimestamp(createdAt)
    || !isTimestamp(expiresAt)
    || createdAt > now
    || expiresAt <= createdAt
    || expiresAt - createdAt > MAX_AUTOFILL_PENDING_SAVE_TTL_MS
    || !isCanonicalBase64(iv, AES_GCM_IV_BYTES, AES_GCM_IV_BYTES)
    || !isCanonicalBase64(ciphertext, 16, MAX_CIPHERTEXT_BYTES)
  ) return undefined;
  const base = {
    entryId,
    ...input,
    createdAt,
    expiresAt,
    iv: iv as string,
    ciphertext: ciphertext as string,
  };
  if (state === 'unconfirmed') return { ...base, confirmation: 'unconfirmed', state };
  if (state === 'pending') return { ...base, confirmation: 'confirmed', state };

  const promptId = dataValue(value, 'promptId');
  const claimDocumentId = dataValue(value, 'claimDocumentId');
  const claimedAt = dataValue(value, 'claimedAt');
  const claimExpiresAt = dataValue(value, 'claimExpiresAt');
  const decisionIv = dataValue(value, 'decisionIv');
  const decisionCiphertext = dataValue(value, 'decisionCiphertext');
  const decisionTagValue = dataValue(value, 'decisionTag');
  if (
    typeof promptId !== 'string'
    || !UUID_V4.test(promptId)
    || typeof claimDocumentId !== 'string'
    || !isOpaqueId(claimDocumentId)
    || !isTimestamp(claimedAt)
    || !isTimestamp(claimExpiresAt)
    || claimedAt < createdAt
    || claimedAt > now
    || claimExpiresAt <= claimedAt
    || claimExpiresAt > expiresAt
    || claimExpiresAt - claimedAt > MAX_AUTOFILL_PENDING_SAVE_CLAIM_LEASE_MS
    || !isCanonicalBase64(decisionIv, AES_GCM_IV_BYTES, AES_GCM_IV_BYTES)
    || !isCanonicalBase64(decisionCiphertext, 16, MAX_CIPHERTEXT_BYTES)
    || !isCanonicalBase64(decisionTagValue, SHA256_BYTES, SHA256_BYTES)
  ) return undefined;
  return {
    ...base,
    confirmation: 'confirmed',
    state,
    promptId,
    claimDocumentId,
    claimedAt,
    claimExpiresAt,
    decisionIv: decisionIv as string,
    decisionCiphertext: decisionCiphertext as string,
    decisionTag: decisionTagValue as string,
  };
}

function toUnclaimed(entry: ClaimedPendingEntry): UnclaimedPendingEntry {
  const {
    promptId: _promptId,
    claimDocumentId: _claimDocumentId,
    claimedAt: _claimedAt,
    claimExpiresAt: _claimExpiresAt,
    decisionIv: _decisionIv,
    decisionCiphertext: _decisionCiphertext,
    decisionTag: _decisionTag,
    ...base
  } = entry;
  return { ...base, state: 'pending' };
}

function credentialAadBase(
  entry: StoredPendingEntry,
  confirmation: AutofillPendingSaveCaptureState,
): Omit<PendingEntryBase, 'iv' | 'ciphertext'> {
  return Object.freeze({
    entryId: entry.entryId,
    tabId: entry.tabId,
    frameId: entry.frameId,
    sourceDocumentId: entry.sourceDocumentId,
    sourceUrl: entry.sourceUrl,
    origin: entry.origin,
    sessionGeneration: entry.sessionGeneration,
    sessionBindingId: entry.sessionBindingId,
    serverGeneration: entry.serverGeneration,
    accountGeneration: entry.accountGeneration,
    serverUrl: entry.serverUrl,
    accountIdentity: entry.accountIdentity,
    policyGeneration: entry.policyGeneration,
    enterprisePolicyGeneration: entry.enterprisePolicyGeneration,
    enterprisePolicyRawGeneration: entry.enterprisePolicyRawGeneration,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
    confirmation,
  });
}

function unconfirmedMetadata(entry: PendingEntryBase): AutofillUnconfirmedSaveMetadata {
  return Object.freeze({
    captureId: entry.entryId,
    tabId: entry.tabId,
    frameId: entry.frameId,
    sourceDocumentId: entry.sourceDocumentId,
    sourceUrl: entry.sourceUrl,
    origin: entry.origin,
    sessionGeneration: entry.sessionGeneration,
    sessionBindingId: entry.sessionBindingId,
    serverGeneration: entry.serverGeneration,
    accountGeneration: entry.accountGeneration,
    serverUrl: entry.serverUrl,
    accountIdentity: entry.accountIdentity,
    policyGeneration: entry.policyGeneration,
    enterprisePolicyGeneration: entry.enterprisePolicyGeneration,
    enterprisePolicyRawGeneration: entry.enterprisePolicyRawGeneration,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
  });
}

function canonicalizeUnconfirmedMetadata(value: unknown): AutofillUnconfirmedSaveMetadata {
  const record = strictInputRecord(value, [
    'captureId', 'tabId', 'frameId', 'sourceDocumentId', 'sourceUrl', 'origin',
    'sessionGeneration', 'sessionBindingId', 'serverGeneration', 'accountGeneration',
    'serverUrl', 'accountIdentity', 'policyGeneration', 'enterprisePolicyGeneration',
    'enterprisePolicyRawGeneration', 'createdAt', 'expiresAt',
  ]);
  const input = canonicalizeInput({
    tabId: dataValue(record, 'tabId'),
    frameId: dataValue(record, 'frameId'),
    sourceDocumentId: dataValue(record, 'sourceDocumentId'),
    sourceUrl: dataValue(record, 'sourceUrl'),
    origin: dataValue(record, 'origin'),
    sessionGeneration: dataValue(record, 'sessionGeneration'),
    sessionBindingId: dataValue(record, 'sessionBindingId'),
    serverGeneration: dataValue(record, 'serverGeneration'),
    accountGeneration: dataValue(record, 'accountGeneration'),
    serverUrl: dataValue(record, 'serverUrl'),
    accountIdentity: dataValue(record, 'accountIdentity'),
    policyGeneration: dataValue(record, 'policyGeneration'),
    enterprisePolicyGeneration: dataValue(record, 'enterprisePolicyGeneration'),
    enterprisePolicyRawGeneration: dataValue(record, 'enterprisePolicyRawGeneration'),
  });
  const captureId = uuid(dataValue(record, 'captureId'), 'captureId');
  const createdAt = dataValue(record, 'createdAt');
  const expiresAt = dataValue(record, 'expiresAt');
  if (!isTimestamp(createdAt) || !isTimestamp(expiresAt)
      || expiresAt <= createdAt || expiresAt - createdAt > MAX_AUTOFILL_PENDING_SAVE_TTL_MS) {
    return invalidInput('unconfirmed capture timestamps are invalid.');
  }
  return Object.freeze({ captureId, ...input, createdAt, expiresAt });
}

function sameUnconfirmedMetadata(
  entry: PendingEntryBase,
  expected: AutofillUnconfirmedSaveMetadata,
): boolean {
  return entry.entryId === expected.captureId
    && entry.tabId === expected.tabId
    && entry.frameId === expected.frameId
    && entry.sourceDocumentId === expected.sourceDocumentId
    && entry.sourceUrl === expected.sourceUrl
    && entry.origin === expected.origin
    && entry.sessionGeneration === expected.sessionGeneration
    && entry.sessionBindingId === expected.sessionBindingId
    && entry.serverGeneration === expected.serverGeneration
    && entry.accountGeneration === expected.accountGeneration
    && entry.serverUrl === expected.serverUrl
    && entry.accountIdentity === expected.accountIdentity
    && entry.policyGeneration === expected.policyGeneration
    && entry.enterprisePolicyGeneration === expected.enterprisePolicyGeneration
    && entry.enterprisePolicyRawGeneration === expected.enterprisePolicyRawGeneration
    && entry.createdAt === expected.createdAt
    && entry.expiresAt === expected.expiresAt;
}

function canonicalizeInput(value: unknown): AutofillPendingSaveInput {
  const record = strictInputRecord(value, [
    'tabId', 'frameId', 'sourceDocumentId', 'sourceUrl', 'origin', 'sessionGeneration',
    'sessionBindingId', 'serverGeneration', 'accountGeneration', 'serverUrl',
    'accountIdentity', 'policyGeneration', 'enterprisePolicyGeneration',
    'enterprisePolicyRawGeneration',
  ]);
  const sourceUrl = canonicalHttpUrl(dataValue(record, 'sourceUrl'), 'sourceUrl');
  const origin = canonicalOrigin(dataValue(record, 'origin'));
  if (new URL(sourceUrl).origin !== origin) invalidInput('origin does not match sourceUrl.');
  return Object.freeze({
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(record, 'frameId'), 'frameId'),
    sourceDocumentId: opaqueId(dataValue(record, 'sourceDocumentId'), 'sourceDocumentId'),
    sourceUrl,
    origin,
    ...canonicalizeSecurityBinding(record),
  });
}

function canonicalizeDocumentContext(value: unknown): AutofillPendingSaveDocumentContext {
  const record = strictInputRecord(value, [
    'tabId', 'frameId', 'documentId', 'frameUrl', 'origin', 'sessionGeneration',
    'sessionBindingId', 'serverGeneration', 'accountGeneration', 'serverUrl',
    'accountIdentity', 'policyGeneration', 'enterprisePolicyGeneration',
    'enterprisePolicyRawGeneration',
  ]);
  const frameUrl = canonicalHttpUrl(dataValue(record, 'frameUrl'), 'frameUrl');
  const origin = canonicalOrigin(dataValue(record, 'origin'));
  if (new URL(frameUrl).origin !== origin) invalidInput('origin does not match frameUrl.');
  return Object.freeze({
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(record, 'frameId'), 'frameId'),
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId'),
    frameUrl,
    origin,
    ...canonicalizeSecurityBinding(record),
  });
}

function canonicalizeSecurityBinding(record: Record<string, unknown>): AutofillPendingSaveSecurityBinding {
  return {
    sessionGeneration: nonNegativeInteger(dataValue(record, 'sessionGeneration'), 'sessionGeneration'),
    sessionBindingId: opaqueId(dataValue(record, 'sessionBindingId'), 'sessionBindingId'),
    serverGeneration: nonNegativeInteger(dataValue(record, 'serverGeneration'), 'serverGeneration'),
    accountGeneration: nonNegativeInteger(dataValue(record, 'accountGeneration'), 'accountGeneration'),
    serverUrl: canonicalServerUrl(dataValue(record, 'serverUrl')),
    accountIdentity: boundedIdentity(dataValue(record, 'accountIdentity'), 'accountIdentity'),
    policyGeneration: nonNegativeInteger(dataValue(record, 'policyGeneration'), 'policyGeneration'),
    enterprisePolicyGeneration: nonNegativeInteger(
      dataValue(record, 'enterprisePolicyGeneration'),
      'enterprisePolicyGeneration',
    ),
    enterprisePolicyRawGeneration: opaqueId(
      dataValue(record, 'enterprisePolicyRawGeneration'),
      'enterprisePolicyRawGeneration',
    ),
  };
}

function canonicalizeCredentials(value: unknown): AutofillPendingSaveCredentials {
  const record = isPlainRecord(value) ? value : invalidInput('credentials are invalid.');
  const hasUsername = Object.hasOwn(record, 'username');
  if (!hasExactDataKeys(record, hasUsername ? ['username', 'password'] : ['password'])) {
    return invalidInput('credentials are invalid.');
  }
  const username = dataValue(record, 'username');
  const password = dataValue(record, 'password');
  if (hasUsername && (typeof username !== 'string' || username.length > MAX_USERNAME_LENGTH)) {
    invalidInput('username is invalid.');
  }
  if (typeof password !== 'string' || password.length === 0 || password.length > MAX_PASSWORD_LENGTH) {
    invalidInput('password is invalid.');
  }
  return Object.freeze({
    ...(hasUsername ? { username: username as string } : {}),
    password,
  });
}

function canonicalizeDecision(value: unknown): AutofillPendingSaveDecision {
  if (!isPlainRecord(value)) return invalidInput('pending-save decision is invalid.');
  const action = dataValue(value, 'action');
  if (action === 'none') {
    if (!hasExactDataKeys(value, ['action'])) invalidInput('pending-save decision is invalid.');
    return Object.freeze({ action });
  }
  if (action === 'save') {
    if (!hasExactDataKeys(value, ['action', 'suggestedName'])) {
      invalidInput('pending-save decision is invalid.');
    }
    return Object.freeze({
      action,
      suggestedName: displayString(dataValue(value, 'suggestedName'), 'suggestedName'),
    });
  }
  if (action === 'update' || action === 'addUri') {
    if (!hasExactDataKeys(value, ['action', 'cipherId', 'name'])) {
      invalidInput('pending-save decision is invalid.');
    }
    return Object.freeze({
      action,
      cipherId: opaqueId(dataValue(value, 'cipherId'), 'cipherId'),
      name: displayString(dataValue(value, 'name'), 'name'),
    });
  }
  return invalidInput('pending-save decision is invalid.');
}

function sameCaptureSlot(left: PendingEntryBase, right: AutofillPendingSaveInput): boolean {
  return sameBrowserOrigin(left, right) && sameSecurityBinding(left, right);
}

function sameClaimScope(
  entry: PendingEntryBase,
  context: AutofillPendingSaveDocumentContext,
): boolean {
  return sameBrowserOrigin(entry, context) && sameSecurityBinding(entry, context);
}

function sameBrowserOrigin(
  left: Pick<PendingEntryBase, 'tabId' | 'frameId' | 'origin'>,
  right: Pick<AutofillPendingSaveDocumentContext, 'tabId' | 'frameId' | 'origin'>,
): boolean {
  return left.tabId === right.tabId && left.frameId === right.frameId && left.origin === right.origin;
}

function sameSecurityBinding(
  left: AutofillPendingSaveSecurityBinding,
  right: AutofillPendingSaveSecurityBinding,
): boolean {
  return left.sessionGeneration === right.sessionGeneration
    && left.sessionBindingId === right.sessionBindingId
    && left.serverGeneration === right.serverGeneration
    && left.accountGeneration === right.accountGeneration
    && left.serverUrl === right.serverUrl
    && left.accountIdentity === right.accountIdentity
    && left.policyGeneration === right.policyGeneration
    && left.enterprisePolicyGeneration === right.enterprisePolicyGeneration
    && left.enterprisePolicyRawGeneration === right.enterprisePolicyRawGeneration;
}

function compareEntriesOldestFirst(left: StoredPendingEntry, right: StoredPendingEntry): number {
  return left.createdAt - right.createdAt || left.entryId.localeCompare(right.entryId);
}

function constantTimeBase64Equal(left: string, right: string): boolean {
  let leftBytes: Uint8Array | undefined;
  let rightBytes: Uint8Array | undefined;
  try {
    leftBytes = canonicalBase64Bytes(left, SHA256_BYTES, SHA256_BYTES);
    rightBytes = canonicalBase64Bytes(right, SHA256_BYTES, SHA256_BYTES);
    let difference = leftBytes.length ^ rightBytes.length;
    const length = Math.max(leftBytes.length, rightBytes.length);
    for (let index = 0; index < length; index += 1) {
      difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
    }
    return difference === 0;
  } catch {
    return false;
  } finally {
    leftBytes?.fill(0);
    rightBytes?.fill(0);
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  const native = (bytes as Uint8Array & { toBase64?: () => string }).toBase64;
  if (typeof native === 'function') return native.call(bytes);
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function canonicalBase64Bytes(value: unknown, minimum: number, maximum: number): Uint8Array {
  if (typeof value !== 'string' || value.length === 0) throw new Error('invalid base64');
  let binary: string;
  try { binary = atob(value); } catch { throw new Error('invalid base64'); }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if (bytes.length < minimum || bytes.length > maximum || bytesToBase64(bytes) !== value) {
    bytes.fill(0);
    throw new Error('invalid base64');
  }
  return bytes;
}

function isCanonicalBase64(value: unknown, minimum: number, maximum: number): value is string {
  let bytes: Uint8Array | undefined;
  try {
    bytes = canonicalBase64Bytes(value, minimum, maximum);
    return true;
  } catch {
    return false;
  } finally {
    bytes?.fill(0);
  }
}

function hasBoundedEnvelopeSize(storageKeyValue: string, envelope: PendingSaveEnvelope): boolean {
  try {
    const serialized = JSON.stringify({ [storageKeyValue]: envelope });
    return typeof serialized === 'string'
      && new TextEncoder().encode(serialized).byteLength
        <= AUTOFILL_PENDING_SAVE_ENVELOPE_MAX_UTF8_BYTES;
  } catch {
    return false;
  }
}

function extractRevision(value: unknown): number | undefined {
  if (!isPlainRecord(value)) return undefined;
  const revision = dataValue(value, 'revision');
  return isRevision(revision) ? revision : undefined;
}

function strictInputRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!isPlainRecord(value) || !hasExactDataKeys(value, keys)) {
    return invalidInput('pending-save input has an invalid shape.');
  }
  return value;
}

function canonicalHttpUrl(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL_LENGTH) {
    return invalidInput(`${name} is invalid.`);
  }
  let url: URL;
  try { url = new URL(value); } catch { return invalidInput(`${name} is invalid.`); }
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:')
    || url.username
    || url.password
    || url.href !== value
  ) return invalidInput(`${name} is not a canonical HTTP(S) URL.`);
  return value;
}

function canonicalOrigin(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL_LENGTH) {
    return invalidInput('origin is invalid.');
  }
  let url: URL;
  try { url = new URL(value); } catch { return invalidInput('origin is invalid.'); }
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:')
    || url.username
    || url.password
    || url.origin !== value
  ) return invalidInput('origin is not canonical.');
  return value;
}

function canonicalServerUrl(value: unknown): string {
  const url = canonicalHttpUrl(value, 'serverUrl');
  const parsed = new URL(url);
  if (parsed.search || parsed.hash) invalidInput('serverUrl must not contain query or fragment.');
  return url;
}

function opaqueId(value: unknown, name: string): string {
  if (!isOpaqueId(value)) return invalidInput(`${name} is invalid.`);
  return value;
}

function isOpaqueId(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= MAX_OPAQUE_ID_LENGTH
    && value.trim() === value
    && !hasAsciiControl(value);
}

function boundedIdentity(value: unknown, name: string): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_ACCOUNT_IDENTITY_LENGTH
    || value.trim() !== value
    || hasAsciiControl(value)
  ) return invalidInput(`${name} is invalid.`);
  return value;
}

function displayString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_DISPLAY_LENGTH) {
    return invalidInput(`${name} is invalid.`);
  }
  return value;
}

function storageKey(value: unknown): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_STORAGE_KEY_LENGTH
    || value.trim() !== value
    || hasAsciiControl(value)
  ) throw configurationError('storageKey must be a bounded canonical string.');
  return value;
}

function hasAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function boundedPositiveInteger(value: unknown, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
    throw configurationError(`${name} must be a positive integer no greater than ${maximum}.`);
  }
  return value as number;
}

function nonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) {
    return invalidInput(`${name} is invalid.`);
  }
  return value as number;
}

function safeDeadline(now: number, duration: number, name: string): number {
  const deadline = now + duration;
  if (!Number.isSafeInteger(deadline) || deadline <= now) {
    throw configurationError(`${name} is invalid.`);
  }
  return deadline;
}

function uuid(value: unknown, name: string): string {
  if (typeof value !== 'string' || !UUID_V4.test(value)) return invalidInput(`${name} is invalid.`);
  return value;
}

function assertEvaluator(value: unknown): asserts value is AutofillPendingSaveEvaluator {
  if (typeof value !== 'function') invalidInput('A pending-save evaluator is required.');
}

function isTimestamp(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && !Object.is(value, -0);
}

function isRevision(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0 && !Object.is(value, -0);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function hasExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(record);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) return false;
  const expectedSet = new Set(expected);
  if (keys.some((key) => !expectedSet.has(key as string))) return false;
  return expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    return descriptor !== undefined && descriptor.enumerable && 'value' in descriptor;
  });
}

function hasDenseArrayShape(value: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) return false;
  }
  return keys.every((key) => key === 'length'
    || (typeof key === 'string'
      && /^(0|[1-9]\d*)$/u.test(key)
      && Number(key) < value.length));
}

function invalidInput(message: string): never {
  throw new AutofillPendingSaveStoreError('invalid_input', message);
}

function configurationError(message: string): AutofillPendingSaveStoreError {
  return new AutofillPendingSaveStoreError('invalid_configuration', message);
}
