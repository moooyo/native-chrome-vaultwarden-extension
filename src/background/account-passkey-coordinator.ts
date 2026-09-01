import { ApiHttpError, type ApiClient } from '../core/api/client.js';
import {
  parseAndBindAccountPasskeyConnectorResult,
} from '../core/api/account-passkey.js';
import type { AccountLeaseGate, ServerLease } from '../core/session/account-gate.js';
import type { AccountPasskeyAuthResult } from '../core/session/auth-service.js';
import {
  ACCOUNT_PASSKEY_ATTEMPT_MAX_TTL_MS,
  assertAccountPasskeyRpIdForConnector,
  deriveAccountPasskeyPrfSalt,
  parseAccountPasskeyConnectorContext,
  sameAccountPasskeyConnector,
  type AccountPasskeyConnectorCeremony,
  type AccountPasskeyConnectorContext,
} from '../core/session/account-passkey.js';
import {
  AccountPasskeyAttemptRegistry,
  type AccountPasskeyAttempt,
  type ClaimedAccountPasskeyAttempt,
  type UnknownAccountPasskeyAttempt,
  type WaitingAccountPasskeyAttempt,
} from './account-passkey-attempt-registry.js';

const NETWORK_SETTLEMENT_GRACE_MS = 60_000;

export type AccountPasskeyAttemptStatus =
  | { readonly status: 'none' }
  | { readonly status: 'waiting'; readonly attemptId: string; readonly expiresAt: number }
  | { readonly status: 'outcome_unknown'; readonly attemptId: string; readonly terminalAt: number };

export type AccountPasskeySubmitOutcome =
  | { readonly status: 'unlocked' | 'locked' | 'restricted' }
  | { readonly status: 'two_factor_unsupported'; readonly providers: readonly number[] }
  | { readonly status: 'failed' | 'expired' | 'replayed' }
  | { readonly status: 'outcome_unknown'; readonly attemptId: string; readonly terminalAt: number };

export type AccountPasskeyCoordinatorErrorCode =
  | 'busy'
  | 'invalid_connector'
  | 'invalid_assertion'
  | 'server_changed'
  | 'request_failed';

export class AccountPasskeyCoordinatorError extends Error {
  constructor(readonly code: AccountPasskeyCoordinatorErrorCode, message: string) {
    super(message);
    this.name = 'AccountPasskeyCoordinatorError';
  }
}

export interface AccountPasskeyCoordinatorDeps {
  readonly api: ApiClient;
  readonly serverGate: Pick<AccountLeaseGate, 'captureServer' | 'assertServer'>;
  readonly attempts: AccountPasskeyAttemptRegistry;
  readonly activate: (input: {
    readonly serverUrl: string;
    readonly token: string;
    readonly assertion: Parameters<ApiClient['accountPasskeyLogin']>[0]['assertion'];
    /** Borrowed only for the awaited activation call; the coordinator zeroes it afterward. */
    readonly prfOutput?: Uint8Array;
  }) => Promise<AccountPasskeyAuthResult>;
  readonly now?: () => number;
  readonly createAttemptId?: () => string;
  readonly derivePrfSalt?: () => Promise<string>;
}

interface ServerContext {
  readonly lease: ServerLease;
  readonly api: ApiClient;
}

/** Coordinates the server-origin connector without exposing its opaque continuation token. */
export class AccountPasskeyCoordinator {
  readonly #now: () => number;
  readonly #createAttemptId: () => string;
  readonly #derivePrfSalt: () => Promise<string>;
  #tail: Promise<void> = Promise.resolve();
  readonly #attemptLeases = new Map<string, ServerLease>();

  constructor(private readonly deps: AccountPasskeyCoordinatorDeps) {
    this.#now = deps.now ?? Date.now;
    this.#createAttemptId = deps.createAttemptId ?? (() => crypto.randomUUID());
    this.#derivePrfSalt = deps.derivePrfSalt ?? deriveAccountPasskeyPrfSalt;
  }

  begin(rawConnector: unknown): Promise<AccountPasskeyConnectorCeremony> {
    return this.#serialize(async () => {
      if (await this.deps.attempts.read()) {
        throw coordinatorError('busy', 'An account passkey attempt is already active.');
      }
      const context = this.#captureServer();
      const connector = this.#parseConnector(rawConnector, context.lease.serverUrl);
      let assertionOptions;
      try {
        assertionOptions = await this.#awaitCurrent(
          context,
          context.api.getAccountPasskeyAssertionOptions(),
        );
      } catch (error) {
        if (error instanceof AccountPasskeyCoordinatorError) throw error;
        throw coordinatorError('request_failed', 'Account passkey options could not be loaded.');
      }
      assertAccountPasskeyRpIdForConnector(assertionOptions.options.rpId, connector);
      const createdAt = this.#currentTime();
      const ttl = Math.min(
        ACCOUNT_PASSKEY_ATTEMPT_MAX_TTL_MS,
        assertionOptions.options.timeout + NETWORK_SETTLEMENT_GRACE_MS,
      );
      const expiresAt = createdAt + ttl;
      if (!Number.isSafeInteger(expiresAt)) {
        throw coordinatorError('request_failed', 'Account passkey attempt lifetime is invalid.');
      }
      const waiting = await this.#awaitCurrent(context, this.deps.attempts.create({
        attemptId: this.#createAttemptId(),
        serverUrl: context.lease.serverUrl,
        connector,
        assertionOptions,
        createdAt,
        expiresAt,
      }));
      this.#attemptLeases.set(waiting.owner.attemptId, context.lease);
      return this.#ceremony(waiting, context);
    });
  }

  resume(rawConnector: unknown): Promise<AccountPasskeyConnectorCeremony | undefined> {
    return this.#serialize(async () => {
      const current = await this.deps.attempts.read();
      if (!current || current.status === 'outcome_unknown') return undefined;
      if (current.status === 'claimed') {
        await this.deps.attempts.markOutcomeUnknown(current.owner);
        this.#attemptLeases.delete(current.owner.attemptId);
        return undefined;
      }
      const context = await this.#contextFor(current);
      if (!context) {
        await this.deps.attempts.clear(current.owner);
        this.#attemptLeases.delete(current.owner.attemptId);
        throw coordinatorError('server_changed', 'The server changed during account passkey login.');
      }
      const connector = this.#parseConnector(rawConnector, current.owner.serverUrl);
      if (!sameAccountPasskeyConnector(connector, current.connector)) {
        throw coordinatorError('invalid_connector', 'The account passkey connector changed.');
      }
      return this.#ceremony(current, context);
    });
  }

  submit(
    rawConnector: unknown,
    attemptId: string,
    rawResult: unknown,
  ): Promise<AccountPasskeySubmitOutcome> {
    return this.#serialize(async () => {
      const current = await this.deps.attempts.read();
      if (!current) return Object.freeze({ status: 'expired' });
      if (current.owner.attemptId !== attemptId) return Object.freeze({ status: 'replayed' });
      if (current.status === 'outcome_unknown') return projectUnknown(current);
      if (current.status === 'claimed') {
        return Object.freeze({ status: 'replayed' });
      }
      const context = await this.#contextFor(current);
      if (!context) {
        await this.deps.attempts.clear(current.owner);
        this.#attemptLeases.delete(current.owner.attemptId);
        throw coordinatorError('server_changed', 'The server changed during account passkey login.');
      }
      const connector = this.#parseConnector(rawConnector, current.owner.serverUrl);
      if (!sameAccountPasskeyConnector(connector, current.connector)) {
        throw coordinatorError('invalid_connector', 'The account passkey connector changed.');
      }

      let parsed;
      try {
        parsed = await parseAndBindAccountPasskeyConnectorResult(
          rawResult,
          current.assertionOptions.options,
          connector.origin,
        );
        this.#assertCurrent(context);
      } catch (error) {
        if (error instanceof AccountPasskeyCoordinatorError) throw error;
        throw coordinatorError('invalid_assertion', 'The account passkey assertion is invalid.');
      }

      let claimed: ClaimedAccountPasskeyAttempt | undefined;
      try {
        claimed = await this.#awaitCurrent(context, this.deps.attempts.claim(current.owner));
        if (!claimed) return Object.freeze({ status: 'replayed' });
        const result = await this.#awaitCurrent(context, this.deps.activate({
          serverUrl: claimed.owner.serverUrl,
          token: claimed.assertionOptions.token,
          assertion: parsed.assertion,
          ...(parsed.prfOutput ? { prfOutput: parsed.prfOutput } : {}),
        }));
        if (result.kind === 'twoFactorUnsupported') {
          if (!await this.deps.attempts.clear(claimed.owner)) return this.#unknown(claimed);
          this.#attemptLeases.delete(claimed.owner.attemptId);
          return Object.freeze({
            status: 'two_factor_unsupported',
            providers: Object.freeze([...result.providers]),
          });
        }
        if (!await this.deps.attempts.clear(claimed.owner)) return this.#unknown(claimed);
        this.#attemptLeases.delete(claimed.owner.attemptId);
        return Object.freeze({ status: result.kind });
      } catch (error) {
        if (!claimed) throw error;
        if (isDefiniteClientFailure(error)) {
          await this.deps.attempts.clear(claimed.owner).catch(() => false);
          this.#attemptLeases.delete(claimed.owner.attemptId);
          return Object.freeze({ status: 'failed' });
        }
        return this.#unknown(claimed);
      } finally {
        parsed.prfOutput?.fill(0);
      }
    });
  }

  startup(): Promise<AccountPasskeyAttemptStatus> {
    return this.#serialize(() => this.#readStatus(true));
  }

  status(): Promise<AccountPasskeyAttemptStatus> {
    return this.#serialize(() => this.#readStatus(false));
  }

  cancel(rawConnector: unknown, attemptId: string): Promise<boolean> {
    return this.#serialize(async () => {
      const current = await this.deps.attempts.read();
      if (!current || current.owner.attemptId !== attemptId) return false;
      if (current.status === 'claimed') {
        await this.deps.attempts.markOutcomeUnknown(current.owner);
        this.#attemptLeases.delete(current.owner.attemptId);
        return false;
      }
      if (current.status === 'outcome_unknown') return false;
      const connector = this.#parseConnector(rawConnector, current.owner.serverUrl);
      if (!sameAccountPasskeyConnector(connector, current.connector)) {
        throw coordinatorError('invalid_connector', 'The account passkey connector changed.');
      }
      const cleared = await this.deps.attempts.clear(current.owner);
      if (cleared) this.#attemptLeases.delete(current.owner.attemptId);
      return cleared;
    });
  }

  async #readStatus(_startup: boolean): Promise<AccountPasskeyAttemptStatus> {
    const current = await this.deps.attempts.read();
    if (!current) return Object.freeze({ status: 'none' });
    if (current.status === 'outcome_unknown') return projectUnknown(current);
    if (current.status === 'claimed') {
      const unknown = await this.deps.attempts.markOutcomeUnknown(current.owner);
      this.#attemptLeases.delete(current.owner.attemptId);
      return unknown ? projectUnknown(unknown) : Object.freeze({ status: 'none' });
    }
    const context = await this.#contextFor(current);
    if (!context) {
      await this.deps.attempts.clear(current.owner);
      this.#attemptLeases.delete(current.owner.attemptId);
      return Object.freeze({ status: 'none' });
    }
    return Object.freeze({
      status: 'waiting',
      attemptId: current.owner.attemptId,
      expiresAt: current.expiresAt,
    });
  }

  async #ceremony(
    waiting: WaitingAccountPasskeyAttempt,
    context: ServerContext,
  ): Promise<AccountPasskeyConnectorCeremony> {
    const prfSalt = await this.#awaitCurrent(context, this.#derivePrfSalt());
    return Object.freeze({
      attemptId: waiting.owner.attemptId,
      options: waiting.assertionOptions.options,
      prfSalt,
      expiresAt: waiting.expiresAt,
    });
  }

  async #unknown(claimed: ClaimedAccountPasskeyAttempt): Promise<AccountPasskeySubmitOutcome> {
    const unknown = await this.deps.attempts.markOutcomeUnknown(claimed.owner).catch(() => undefined);
    this.#attemptLeases.delete(claimed.owner.attemptId);
    return unknown
      ? projectUnknown(unknown)
      : Object.freeze({
          status: 'outcome_unknown',
          attemptId: claimed.owner.attemptId,
          terminalAt: this.#currentTime(),
        });
  }

  #captureServer(): ServerContext {
    let lease: ServerLease;
    try {
      lease = this.deps.serverGate.captureServer();
      this.deps.serverGate.assertServer(lease);
    } catch {
      throw coordinatorError('server_changed', 'No stable server is available for account passkey login.');
    }
    const api = this.deps.api.forServer(lease.serverUrl).withRequestGuard(() => {
      this.#assertCurrent({ lease });
    });
    return { lease, api };
  }

  async #contextFor(attempt: AccountPasskeyAttempt): Promise<ServerContext | undefined> {
    const existing = this.#attemptLeases.get(attempt.owner.attemptId);
    if (existing) {
      try {
        this.deps.serverGate.assertServer(existing);
      } catch {
        return undefined;
      }
      if (existing.serverUrl !== attempt.owner.serverUrl) return undefined;
      return {
        lease: existing,
        api: this.deps.api.forServer(existing.serverUrl).withRequestGuard(() => {
          this.#assertCurrent({ lease: existing });
        }),
      };
    }
    let context: ServerContext;
    try {
      context = this.#captureServer();
    } catch {
      return undefined;
    }
    if (context.lease.serverUrl !== attempt.owner.serverUrl) return undefined;
    this.#attemptLeases.set(attempt.owner.attemptId, context.lease);
    return context;
  }

  #assertCurrent(context: Pick<ServerContext, 'lease'>): void {
    try {
      this.deps.serverGate.assertServer(context.lease);
    } catch {
      throw coordinatorError('server_changed', 'The server changed during account passkey login.');
    }
  }

  async #awaitCurrent<T>(context: ServerContext, operation: PromiseLike<T>): Promise<T> {
    const result = await operation;
    this.#assertCurrent(context);
    return result;
  }

  #parseConnector(input: unknown, serverUrl: string): AccountPasskeyConnectorContext {
    try {
      return parseAccountPasskeyConnectorContext(input, serverUrl);
    } catch {
      throw coordinatorError('invalid_connector', 'The account passkey connector is invalid.');
    }
  }

  #currentTime(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw coordinatorError('request_failed', 'The account passkey clock is invalid.');
    }
    return now;
  }

  #serialize<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.#tail.then(operation, operation);
    this.#tail = run.then(() => undefined, () => undefined);
    return run;
  }
}

function projectUnknown(
  attempt: UnknownAccountPasskeyAttempt,
): Extract<AccountPasskeyAttemptStatus | AccountPasskeySubmitOutcome, { status: 'outcome_unknown' }> {
  return Object.freeze({
    status: 'outcome_unknown',
    attemptId: attempt.owner.attemptId,
    terminalAt: attempt.terminalAt,
  });
}

function isDefiniteClientFailure(error: unknown): error is ApiHttpError {
  return error instanceof ApiHttpError && error.status >= 400 && error.status < 500;
}

function coordinatorError(
  code: AccountPasskeyCoordinatorErrorCode,
  message: string,
): AccountPasskeyCoordinatorError {
  return new AccountPasskeyCoordinatorError(code, message);
}
