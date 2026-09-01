import { ApiHttpError, type ApiClient } from '../core/api/client.js';
import { base64ToBytes } from '../core/crypto/encoding.js';
import type { SymmetricKey } from '../core/crypto/keys.js';
import { FINGERPRINT_WORDLIST } from '../core/generator/wordlist.js';
import type {
  CompleteDeviceLoginInput,
  DeviceLoginAuthResult,
  DeviceLoginActivationStage,
  NewDeviceVerificationAuthResult,
  SessionTransitionEvent,
} from '../core/session/auth-service.js';
import type { AccountLeaseGate, ServerLease } from '../core/session/account-gate.js';
import type { MasterPasswordPolicy } from '../core/policy/master-password-policy.js';
import {
  DEVICE_LOGIN_AUTH_REQUEST_TYPE,
  bindDeviceLoginRequest,
  createDeviceLoginRequest,
  deriveDeviceLoginFingerprint,
  parseAuthRequestResponse,
  recoverApprovedDeviceLogin,
  type DeviceLoginBoundState,
} from '../core/session/device-login.js';
import {
  parseFido2TwoFactorRequest,
  validateFido2TwoFactorSubmission,
  type Fido2TwoFactorRequest,
} from '../core/session/fido2-two-factor.js';
import {
  createDuoChallengeOwner,
  extractDuoProviderSeed,
  sameDuoChallengeOwner,
  type DuoChallengeOwner,
  type DuoProviderSeed,
  type DuoTwoFactorProvider,
} from '../core/session/duo-two-factor.js';
import {
  createInteractiveTwoFactorChallenge,
  createInteractiveTwoFactorLaunch,
  createInteractiveTwoFactorOwner,
  interactiveTwoFactorConnectorUrl,
  parseInteractiveTwoFactorDocumentId,
  sameInteractiveTwoFactorOwner,
  type InteractiveTwoFactorBeginInput,
  type InteractiveTwoFactorBroker,
  type InteractiveTwoFactorConnectorCaller,
  type InteractiveTwoFactorLaunch,
  type InteractiveTwoFactorLaunchBinding,
  type InteractiveTwoFactorOwner,
  type InteractiveTwoFactorSubmission,
  type InteractiveTwoFactorTabBinding,
} from '../core/session/interactive-two-factor.js';
import type {
  DeviceLoginNotifications,
  DeviceLoginNotificationsAlarm,
} from './device-login-notifications.js';
import type { VaultNotificationsAlarmScheduler } from './vault-notifications.js';
import {
  DeviceLoginStateStore,
  type ActiveDeviceLoginBoundStateSnapshot,
  type ActiveDeviceLoginStateSnapshot,
  type ClaimedDeviceLoginStateSnapshot,
  type DeviceLoginOutcomeUnknownSnapshot,
  type DeviceLoginStateOwner,
  type DeviceLoginStateReadResult,
  type DeviceLoginStateSnapshot,
  type DeviceLoginStoredFido2Challenge,
  type DeviceLoginStoredTwoFactorChallenge,
} from './device-login-state-store.js';

export const DEVICE_LOGIN_STATUS_ALARM_PREFIX = 'device-login-status:';
export const DEVICE_LOGIN_DEADLINE_ALARM_PREFIX = 'device-login-deadline:';
export const DEVICE_LOGIN_STATUS_POLL_INTERVAL_MS = 15_000;

const DEVICE_TYPE = 2;
const DEVICE_NAME = 'chrome';
const EMAIL_PROVIDER = 1;
const FIDO2_PROVIDER = 7;
const DIRECT_CODE_PROVIDERS = new Set([0, 1, 3]);
const MAX_TWO_FACTOR_CODE_LENGTH = 32 * 1024;

export type DeviceLoginCoordinatorErrorCode =
  | 'busy'
  | 'server_changed'
  | 'request_failed'
  | 'invalid_response'
  | 'invalid_input';

export class DeviceLoginCoordinatorError extends Error {
  constructor(readonly code: DeviceLoginCoordinatorErrorCode, message: string) {
    super(message);
    this.name = 'DeviceLoginCoordinatorError';
  }
}

export interface DeviceLoginPublicContext {
  readonly generation: number;
  readonly fingerprint: string;
  readonly serverOrigin: string;
  readonly email: string;
  readonly deviceName: string;
  readonly expiresAt: number;
}

export interface DeviceLoginInteractiveChallenge {
  readonly owner: InteractiveTwoFactorOwner;
}

export type DeviceLoginCoordinatorResult =
  | { readonly status: 'none' }
  | { readonly status: 'not_known_device' }
  | ({ readonly status: 'pending' } & DeviceLoginPublicContext)
  | ({
      readonly status: 'two_factor';
      readonly providers: readonly number[];
      readonly fido2?: DeviceLoginInteractiveChallenge;
    }
      & DeviceLoginPublicContext)
  | ({
      readonly status: 'retry_required';
      readonly providers?: readonly number[];
      readonly fido2?: DeviceLoginInteractiveChallenge;
    }
      & DeviceLoginPublicContext)
  | ({ readonly status: 'two_factor_unsupported'; readonly providers: readonly number[] }
      & DeviceLoginPublicContext)
  | { readonly status: 'denied' | 'expired' | 'restricted' | 'unlocked' }
  | {
      readonly status: 'outcome_unknown';
      readonly generation: number;
      readonly serverOrigin: string;
      readonly createdAt: number;
      readonly expiresAt: number;
      readonly terminalAt: number;
    };

export interface DeviceLoginCoordinatorDeps {
  readonly api: ApiClient;
  readonly serverGate: Pick<AccountLeaseGate, 'captureServer' | 'assertServer'>;
  readonly stateStore: DeviceLoginStateStore;
  readonly notifications: Pick<DeviceLoginNotifications, 'start' | 'stop' | 'handleAlarm'>;
  readonly alarms: VaultNotificationsAlarmScheduler;
  readonly activate: (input: {
    readonly state: DeviceLoginBoundState;
    readonly userKey: SymmetricKey;
    readonly serverUrl: string;
    readonly twoFactor?: NonNullable<CompleteDeviceLoginInput['twoFactor']>;
    readonly forcePasswordReset?: true;
    readonly masterPasswordPolicy?: MasterPasswordPolicy;
    readonly transitionOwner: InteractiveTwoFactorOwner;
    readonly assertTransitionOwnerCurrent: () => void;
    readonly reportActivationStage: (stage: DeviceLoginActivationStage) => void;
  }) => Promise<DeviceLoginAuthResult | NewDeviceVerificationAuthResult>;
  readonly getNotificationsUrl?: (
    lease: ServerLease,
  ) => string | undefined | PromiseLike<string | undefined>;
  readonly closeInteractiveTwoFactorConnector?: (
    document: InteractiveTwoFactorConnectorCaller,
  ) => void | PromiseLike<void>;
  readonly now?: () => number;
}

interface ServerContext {
  readonly lease: ServerLease;
  readonly api: ApiClient;
  readonly authorizationEpoch: number;
}

type ResponseClassification =
  | { readonly kind: 'pending' }
  | { readonly kind: 'denied' }
  | { readonly kind: 'approved'; readonly raw: unknown };

type Observation =
  | { readonly kind: 'unavailable' | 'pending' }
  | { readonly kind: 'settled'; readonly result: DeviceLoginCoordinatorResult };

type DeviceLoginActivationResult = DeviceLoginAuthResult | NewDeviceVerificationAuthResult;

interface DeviceLoginInteractiveRuntime {
  readonly owner: InteractiveTwoFactorOwner;
  readonly request: Fido2TwoFactorRequest;
  readonly expectedUrl: string;
  readonly tabId?: number;
  readonly documentId?: string;
}

export class DeviceLoginCoordinator {
  readonly #now: () => number;
  readonly interactiveTwoFactor: InteractiveTwoFactorBroker<DeviceLoginCoordinatorResult>;
  #tail: Promise<void> = Promise.resolve();
  #statusFlight: {
    readonly expectedGeneration?: number;
    readonly promise: Promise<DeviceLoginCoordinatorResult>;
  } | undefined;
  #notificationGeneration: number | undefined;
  #ceremonyLease: ServerLease | undefined;
  #interactiveRuntime: DeviceLoginInteractiveRuntime | undefined;
  #authorizationEpoch = 0;
  #activationOwner: InteractiveTwoFactorOwner | undefined;
  #connectorPendingCleanup: InteractiveTwoFactorConnectorCaller | undefined;
  #cancellableOwner: DeviceLoginStateOwner | undefined;

  constructor(private readonly deps: DeviceLoginCoordinatorDeps) {
    this.#now = deps.now ?? Date.now;
    this.interactiveTwoFactor = Object.freeze({
      begin: (input: InteractiveTwoFactorBeginInput) => this.#beginInteractiveTwoFactor(input),
      cancelLaunch: (input: InteractiveTwoFactorLaunchBinding) => (
        this.#cancelInteractiveTwoFactorLaunch(input)
      ),
      bindTab: (input: InteractiveTwoFactorTabBinding) => this.#bindInteractiveTwoFactorTab(input),
      matchCaller: (input: InteractiveTwoFactorConnectorCaller) => (
        this.#matchInteractiveTwoFactorCaller(input)
      ),
      complete: (input: InteractiveTwoFactorSubmission) => this.#completeInteractiveTwoFactor(input),
    });
  }

  begin(email: string): Promise<DeviceLoginCoordinatorResult> {
    return this.#serialize(async () => {
      if (await this.deps.stateStore.read()) {
        throw coordinatorError('busy', 'A device login request is already active.');
      }
      const context = this.#captureServer();
      this.#ceremonyLease = context.lease;
      let deviceIdentifier: string;
      let known: boolean;
      try {
        deviceIdentifier = await this.#awaitCurrent(
          context,
          context.api.getDeviceIdentifier(),
        );
        known = await this.#awaitCurrent(
          context,
          context.api.isKnownDevice({ email, deviceIdentifier }),
        );
      } catch (error) {
        if (error instanceof DeviceLoginCoordinatorError) throw error;
        throw coordinatorError('request_failed', 'The known-device check failed.');
      }
      if (!known) return Object.freeze({ status: 'not_known_device' });

      const created = await this.#awaitCurrent(
        context,
        createDeviceLoginRequest({
          email,
          device: { type: DEVICE_TYPE, name: DEVICE_NAME, identifier: deviceIdentifier },
        }, this.#currentTime()),
      );
      const pending = await this.#awaitCurrent(
        context,
        this.deps.stateStore.write(context.lease.serverUrl, created.state),
      );
      let rawCreation: unknown;
      try {
        rawCreation = await this.#awaitCurrent(context, context.api.createAuthRequest({
          email: created.request.email,
          publicKey: created.request.publicKey,
          deviceIdentifier: created.request.deviceIdentifier,
          accessCode: created.request.accessCode,
          type: DEVICE_LOGIN_AUTH_REQUEST_TYPE,
        }));
      } catch (error) {
        if (isDefiniteClientFailure(error)) {
          await this.#clearExact(pending.owner);
          throw coordinatorError('request_failed', 'The device login request could not be created.');
        }
        return this.#outcomeFromActive(pending);
      }

      let boundState: DeviceLoginBoundState;
      try {
        boundState = await this.#awaitCurrent(
          context,
          bindDeviceLoginRequest(created.state, rawCreation, this.#currentTime()),
        );
      } catch {
        return this.#outcomeFromActive(pending);
      }
      const bound = await this.#awaitCurrent(
        context,
        this.deps.stateStore.replace(pending.owner, boundState),
      );
      if (!bound) throw coordinatorError('server_changed', 'The device login request changed.');
      return this.#observeBound(bound, context);
    });
  }

  startup(): Promise<DeviceLoginCoordinatorResult> {
    return this.#serialize(() => this.#readAndObserve(true));
  }

  status(expectedGeneration?: number): Promise<DeviceLoginCoordinatorResult> {
    if (expectedGeneration !== undefined) assertExpectedGeneration(expectedGeneration);
    if (this.#statusFlight && this.#statusFlight.expectedGeneration === expectedGeneration) {
      return this.#statusFlight.promise;
    }
    const operation = this.#serialize(() => this.#readAndObserve(false, expectedGeneration));
    const tracked = operation.finally(() => {
      if (this.#statusFlight?.promise === tracked) this.#statusFlight = undefined;
    });
    this.#statusFlight = {
      ...(expectedGeneration !== undefined ? { expectedGeneration } : {}),
      promise: tracked,
    };
    return tracked;
  }

  handleSignal(): Promise<DeviceLoginCoordinatorResult> {
    return this.status();
  }

  revokeForSessionTransition(event: SessionTransitionEvent): Promise<void> {
    if (event.phase !== 'start') return Promise.resolve();
    if (
      event.owner
      && this.#activationOwner
      && sameOwnerOrFalse(event.owner, this.#activationOwner)
    ) return Promise.resolve();
    return this.cancelCurrent().then(() => undefined);
  }

  handleAlarm(
    alarm: string | DeviceLoginNotificationsAlarm,
  ): Promise<DeviceLoginCoordinatorResult | void> {
    const name = typeof alarm === 'string' ? alarm : alarm.name;
    if (name.startsWith(DEVICE_LOGIN_DEADLINE_ALARM_PREFIX)) {
      return this.#serialize(() => this.#handleDeadlineAlarm(name));
    }
    if (!name.startsWith(DEVICE_LOGIN_STATUS_ALARM_PREFIX)) {
      return this.deps.notifications.handleAlarm(alarm);
    }
    const prearmed = this.#prearmPoll(name);
    return prearmed.then(() => this.#serialize(() => this.#handlePollAlarm(name)));
  }

  retryActivation(expectedGeneration: number): Promise<DeviceLoginCoordinatorResult> {
    assertExpectedGeneration(expectedGeneration);
    return this.#serialize(async () => {
      const current = await this.deps.stateStore.read();
      assertCurrentGeneration(current, expectedGeneration);
      const active = activeBound(current);
      if (!active) return resultForNonActive(current);
      if (active.twoFactor) return this.#publicTwoFactor(active);
      const context = await this.#contextFor(active.owner);
      if (!context) return this.#retireServerMismatch(active);
      if (!active.retryRequired) return this.#publicPending(active, context);
      return this.#explicitActivation(active, context);
    });
  }

  submitTwoFactor(input: {
    readonly generation: number;
    readonly provider: number;
    readonly code: string;
    readonly remember?: boolean;
  }): Promise<DeviceLoginCoordinatorResult> {
    const submitted = parseTwoFactorSubmission(input);
    return this.#serialize(async () => {
      const current = await this.deps.stateStore.read();
      assertCurrentGeneration(current, submitted.generation);
      const active = activeBound(current);
      if (!active?.twoFactor) return resultForNonActive(current);
      if (!active.twoFactor.providers.includes(submitted.provider)) {
        throw coordinatorError('invalid_input', 'The selected two-factor provider is unavailable.');
      }
      if (submitted.provider === FIDO2_PROVIDER) {
        throw coordinatorError('invalid_input', 'Use the interactive security-key connector.');
      }
      if (!DIRECT_CODE_PROVIDERS.has(submitted.provider)) {
        throw coordinatorError('invalid_input', 'The selected two-factor provider is unsupported.');
      }
      const twoFactor: CompleteDeviceLoginInput['twoFactor'] = Object.freeze({
        provider: submitted.provider as 0 | 1 | 3,
        code: submitted.code,
        ...(submitted.remember !== undefined ? { remember: submitted.remember } : {}),
      });
      const context = await this.#contextFor(active.owner);
      return context
        ? this.#explicitActivation(active, context, twoFactor)
        : this.#retireServerMismatch(active);
    });
  }

  prepareDuoTwoFactor(input: {
    readonly generation: number;
    readonly provider: DuoTwoFactorProvider;
  }): Promise<{ readonly owner: DuoChallengeOwner; readonly seed: DuoProviderSeed }> {
    return this.#serialize(async () => {
      const current = await this.deps.stateStore.read();
      assertCurrentGeneration(current, input.generation);
      const active = activeBound(current);
      const seed = active?.twoFactor?.duo?.find((entry) => entry.provider === input.provider);
      if (!active || !seed || !active.twoFactor?.providers.includes(input.provider)) {
        throw coordinatorError('invalid_input', 'The Duo challenge is unavailable.');
      }
      if (!await this.#contextFor(active.owner)) {
        throw coordinatorError('server_changed', 'The configured server changed.');
      }
      return Object.freeze({
        owner: createDuoChallengeOwner({
          flow: 'deviceLogin',
          generation: active.owner.generation,
          serverUrl: active.owner.serverUrl,
          email: active.state.email,
          provider: input.provider,
          bindingId: active.state.requestId,
        }),
        seed,
      });
    });
  }

  completeDuoTwoFactor(input: {
    readonly owner: DuoChallengeOwner;
    readonly token: string;
    readonly remember: boolean;
    readonly onGrantStarted: () => Promise<void>;
    readonly onGrantDispatched: () => void;
  }): Promise<DeviceLoginCoordinatorResult> {
    return this.#serialize(async () => {
      const owner = createDuoChallengeOwner(input.owner);
      if (owner.flow !== 'deviceLogin') throw coordinatorError('invalid_input', 'Invalid Duo flow.');
      const current = await this.deps.stateStore.read();
      assertCurrentGeneration(current, owner.generation);
      const active = activeBound(current);
      const seed = active?.twoFactor?.duo?.find((entry) => entry.provider === owner.provider);
      if (!active || !seed) throw coordinatorError('invalid_input', 'The Duo challenge is unavailable.');
      const expected = createDuoChallengeOwner({
        flow: 'deviceLogin',
        generation: active.owner.generation,
        serverUrl: active.owner.serverUrl,
        email: active.state.email,
        provider: owner.provider,
        bindingId: active.state.requestId,
      });
      if (!sameDuoChallengeOwner(owner, expected)) {
        throw coordinatorError('server_changed', 'The Duo challenge changed.');
      }
      const context = await this.#contextFor(active.owner);
      if (!context) return this.#retireServerMismatch(active);
      return this.#explicitActivation(active, context, Object.freeze({
        provider: owner.provider,
        code: input.token,
        remember: input.remember,
      }), {
        onGrantStarted: input.onGrantStarted,
        onGrantDispatched: input.onGrantDispatched,
      });
    });
  }

  #beginInteractiveTwoFactor(
    input: InteractiveTwoFactorBeginInput,
  ): Promise<InteractiveTwoFactorLaunch> {
    return this.#serialize(async () => {
      const owner = parseDeviceInteractiveOwner(input.owner);
      const current = activeBound(await this.deps.stateStore.read());
      if (!current?.twoFactor?.fido2
          || !sameInteractiveTwoFactorOwner(owner, deviceInteractiveOwner(current.owner))) {
        throw coordinatorError('invalid_input', 'The security-key challenge is no longer available.');
      }
      const previous = this.#interactiveRuntime;
      if (previous
          && sameInteractiveTwoFactorOwner(previous.owner, owner)
          && previous.tabId === undefined) {
        throw coordinatorError('busy', 'The security-key connector is already opening.');
      }
      const request = restoreDeviceLoginFido2Request(current.twoFactor.fido2, owner.serverUrl);
      const challenge = createInteractiveTwoFactorChallenge({
        owner,
        connectorData: request.connectorData,
        connectorUrl: current.twoFactor.fido2.connectorUrl,
      });
      const replace = previous?.tabId !== undefined && previous.documentId
        ? Object.freeze({
            tabId: previous.tabId,
            documentId: previous.documentId,
            url: previous.expectedUrl,
          })
        : undefined;
      const launch = createInteractiveTwoFactorLaunch(
        challenge,
        { parentUrl: input.parentUrl, locale: input.locale },
        replace,
      );
      this.#interactiveRuntime = {
        owner,
        request,
        expectedUrl: launch.url,
      };
      return launch;
    });
  }

  #cancelInteractiveTwoFactorLaunch(
    input: InteractiveTwoFactorLaunchBinding,
  ): Promise<boolean> {
    return this.#serialize(async () => {
      const owner = parseDeviceInteractiveOwner(input.owner);
      const current = this.#interactiveRuntime;
      if (!current
          || current.tabId !== undefined
          || current.expectedUrl !== input.url
          || !sameInteractiveTwoFactorOwner(current.owner, owner)) return false;
      this.#interactiveRuntime = undefined;
      return true;
    });
  }

  #bindInteractiveTwoFactorTab(input: InteractiveTwoFactorTabBinding): Promise<void> {
    return this.#serialize(async () => {
      const owner = parseDeviceInteractiveOwner(input.owner);
      if (!Number.isSafeInteger(input.tabId) || input.tabId < 0) {
        throw coordinatorError('invalid_input', 'The security-key connector tab is invalid.');
      }
      const documentId = parseConnectorDocumentId(input.documentId);
      const runtime = this.#interactiveRuntime;
      const current = activeBound(await this.deps.stateStore.read());
      if (!runtime
          || runtime.tabId !== undefined
          || runtime.expectedUrl !== input.url
          || !sameInteractiveTwoFactorOwner(runtime.owner, owner)) {
        throw coordinatorError('invalid_input', 'The security-key launch binding is invalid.');
      }
      if (!current?.twoFactor?.fido2
          || !sameInteractiveTwoFactorOwner(owner, deviceInteractiveOwner(current.owner))) {
        this.#interactiveRuntime = undefined;
        throw coordinatorError('invalid_input', 'The security-key challenge is no longer available.');
      }
      this.#interactiveRuntime = { ...runtime, tabId: input.tabId, documentId };
    });
  }

  #matchInteractiveTwoFactorCaller(
    input: InteractiveTwoFactorConnectorCaller,
  ): InteractiveTwoFactorOwner | undefined {
    const current = this.#interactiveRuntime;
    return current?.tabId === input.tabId
      && current.documentId === input.documentId
      && current.expectedUrl === input.url
      ? current.owner
      : undefined;
  }

  #completeInteractiveTwoFactor(
    input: InteractiveTwoFactorSubmission,
  ): Promise<DeviceLoginCoordinatorResult> {
    return this.#serialize(async () => {
      const owner = parseDeviceInteractiveOwner(input.owner);
      const documentId = parseConnectorDocumentId(input.documentId);
      if (typeof input.remember !== 'boolean') {
        throw coordinatorError('invalid_input', 'The security-key response is invalid.');
      }
      const runtime = this.#interactiveRuntime;
      const current = activeBound(await this.deps.stateStore.read());
      if (!runtime
          || runtime.tabId !== input.tabId
          || runtime.documentId !== documentId
          || runtime.expectedUrl !== input.url
          || !sameInteractiveTwoFactorOwner(runtime.owner, owner)) {
        throw coordinatorError('invalid_input', 'The security-key connector is not current.');
      }
      if (!current?.twoFactor?.fido2
          || !sameInteractiveTwoFactorOwner(owner, deviceInteractiveOwner(current.owner))) {
        this.#interactiveRuntime = undefined;
        throw coordinatorError('invalid_input', 'The security-key connector is not current.');
      }

      // An exact connector callback gets one validator binding, even when its assertion is invalid.
      this.#interactiveRuntime = undefined;
      let assertion: Awaited<ReturnType<typeof validateFido2TwoFactorSubmission>>;
      try {
        assertion = await validateFido2TwoFactorSubmission(
          input.token,
          runtime.request,
          input.remember,
        );
      } catch {
        throw coordinatorError('invalid_input', 'The security-key response is invalid.');
      }
      const context = await this.#contextFor(current.owner);
      return context
        ? this.#explicitActivation(current, context, {
            provider: FIDO2_PROVIDER,
            assertion,
          })
        : this.#retireServerMismatch(current);
    });
  }

  sendEmailCode(expectedGeneration: number): Promise<void> {
    assertExpectedGeneration(expectedGeneration);
    return this.#serialize(async () => {
      const current = await this.deps.stateStore.read();
      assertCurrentGeneration(current, expectedGeneration);
      const active = activeBound(current);
      if (!active?.twoFactor
          || !active.twoFactor.providers.includes(EMAIL_PROVIDER)
          || !active.twoFactor.token) {
        throw coordinatorError('invalid_input', 'An email two-factor challenge is not available.');
      }
      const context = await this.#contextFor(active.owner);
      if (!context) {
        await this.#retireServerMismatch(active);
        throw coordinatorError('server_changed', 'The configured server changed.');
      }
      try {
        await this.#awaitCurrent(context, context.api.sendEmailLogin({
          email: active.state.email,
          twoFactorToken: active.twoFactor.token,
        }));
      } catch (error) {
        if (error instanceof DeviceLoginCoordinatorError) throw error;
        throw coordinatorError('request_failed', 'The email code could not be requested.');
      }
    });
  }

  cancel(expectedGeneration: number): Promise<boolean> {
    assertExpectedGeneration(expectedGeneration);
    const visibleOwner = this.#cancellableOwner;
    const synchronouslyRevoked = visibleOwner?.generation === expectedGeneration;
    if (synchronouslyRevoked) this.#invalidateAuthorization();
    return this.#serialize(async () => {
      const current = await this.deps.stateStore.read();
      if (!current) {
        await this.#stopOrphanedRuntime(expectedGeneration);
        return false;
      }
      if (synchronouslyRevoked) {
        if (!sameCancellationLineage(current.owner, visibleOwner)) {
          throw coordinatorError('invalid_input', 'The device-login request owner changed.');
        }
      } else {
        assertCurrentGeneration(current, expectedGeneration);
        this.#invalidateAuthorization();
      }
      const cleared = await this.deps.stateStore.clear(current.owner);
      await this.#stopRuntime(current.owner);
      return cleared;
    });
  }

  cancelCurrent(): Promise<boolean> {
    this.#invalidateAuthorization();
    return this.#serialize(async () => {
      const current = await this.deps.stateStore.read();
      if (!current) {
        await this.#stopOrphanedRuntime();
        return false;
      }
      const cleared = await this.deps.stateStore.clear(current.owner);
      await this.#stopRuntime(current.owner);
      return cleared;
    });
  }

  async #readAndObserve(
    _startup: boolean,
    expectedGeneration?: number,
  ): Promise<DeviceLoginCoordinatorResult> {
    const current = await this.deps.stateStore.read();
    if (!current) {
      await this.#stopOrphanedRuntime(expectedGeneration);
      if (expectedGeneration !== undefined) assertCurrentGeneration(current, expectedGeneration);
      return Object.freeze({ status: 'none' });
    }
    if (expectedGeneration !== undefined) assertCurrentGeneration(current, expectedGeneration);
    if (isOutcomeUnknown(current)) return publicOutcomeUnknown(current);
    if (current.claimed) {
      const outcome = await this.deps.stateStore.markOutcomeUnknown(current.owner);
      await this.#stopRuntime(current.owner);
      return outcome ? publicOutcomeUnknown(outcome) : Object.freeze({ status: 'none' });
    }
    if (current.state.phase === 'pending') {
      const outcome = await this.deps.stateStore.retireOutcomeUnknown(current.owner);
      await this.#stopRuntime(current.owner);
      return outcome ? publicOutcomeUnknown(outcome) : Object.freeze({ status: 'none' });
    }
    const active = current as ActiveDeviceLoginBoundStateSnapshot;
    const context = await this.#contextFor(active.owner);
    if (!context) return this.#retireServerMismatch(active);
    if (active.twoFactor && !active.retryRequired) return this.#publicTwoFactor(active);
    if (active.retryRequired) return this.#publicRetry(active);
    return this.#observeBound(active, context);
  }

  async #observeBound(
    current: ActiveBoundSnapshot,
    context: ServerContext,
  ): Promise<DeviceLoginCoordinatorResult> {
    try {
      if (!await this.#schedulePoll(current, context)) return Object.freeze({ status: 'expired' });
    } catch {
      return this.#outcomeFromActive(current);
    }
    const first = await this.#observeOnce(current, context);
    if (first.kind === 'settled') return first.result;

    if (this.#notificationGeneration !== current.owner.generation) {
      await this.#startNotifications(current, context);
      const second = await this.#observeOnce(current, context);
      if (second.kind === 'settled') return second.result;
    }
    return this.#publicPending(current, context);
  }

  async #observeOnce(
    current: ActiveBoundSnapshot,
    context: ServerContext,
  ): Promise<Observation> {
    let raw: unknown;
    try {
      raw = await this.#awaitCurrent(
        context,
        context.api.getAuthRequestResponse(current.state.requestId, current.state.accessCode),
      );
    } catch {
      return { kind: 'unavailable' };
    }

    const observedAt = this.#currentTime();
    if (observedAt >= current.state.expiresAt) {
      await this.#clearExact(current.owner);
      await this.#stopRuntime(current.owner);
      return { kind: 'settled', result: Object.freeze({ status: 'expired' }) };
    }
    let classification: ResponseClassification;
    try {
      classification = classifyResponse(current.state, raw, observedAt);
    } catch {
      return { kind: 'unavailable' };
    }
    if (classification.kind === 'pending') return { kind: 'pending' };
    if (classification.kind === 'denied') {
      await this.#clearExact(current.owner);
      await this.#stopRuntime(current.owner);
      return { kind: 'settled', result: Object.freeze({ status: 'denied' }) };
    }
    return {
      kind: 'settled',
      result: await this.#redeem(current, classification.raw, context),
    };
  }

  async #explicitActivation(
    current: ActiveBoundSnapshot,
    context: ServerContext,
    twoFactor?: NonNullable<CompleteDeviceLoginInput['twoFactor']>,
    lifecycle?: {
      readonly onGrantStarted: () => Promise<void>;
      readonly onGrantDispatched: () => void;
    },
  ): Promise<DeviceLoginCoordinatorResult> {
    let raw: unknown;
    try {
      raw = await this.#awaitCurrent(
        context,
        context.api.getAuthRequestResponse(current.state.requestId, current.state.accessCode),
      );
    } catch {
      return this.#publicRetry(current);
    }
    let classification: ResponseClassification;
    try {
      classification = classifyResponse(current.state, raw, this.#currentTime());
    } catch {
      return this.#publicRetry(current);
    }
    if (classification.kind === 'pending') return this.#publicPending(current, context);
    if (classification.kind === 'denied') {
      await this.#clearExact(current.owner);
      await this.#stopRuntime(current.owner);
      return Object.freeze({ status: 'denied' });
    }
    return this.#redeem(current, classification.raw, context, twoFactor, lifecycle);
  }

  async #redeem(
    current: ActiveBoundSnapshot,
    raw: unknown,
    context: ServerContext,
    twoFactor?: NonNullable<CompleteDeviceLoginInput['twoFactor']>,
    lifecycle?: {
      readonly onGrantStarted: () => Promise<void>;
      readonly onGrantDispatched: () => void;
    },
  ): Promise<DeviceLoginCoordinatorResult> {
    const claimed = await this.#awaitCurrent(
      context,
      this.deps.stateStore.claim(current.owner),
    );
    if (!claimed) throw coordinatorError('server_changed', 'The device login request changed.');
    await this.#stopRuntime(current.owner);
    try {
      if (!await this.#scheduleWatchdog(claimed.owner, claimed.state.expiresAt, context)) {
        return Object.freeze({ status: 'expired' });
      }
    } catch (error) {
      if (lifecycle) {
        await this.#releaseForRetry(claimed, current.twoFactor, context);
        throw error;
      }
      return this.#outcomeFromClaim(claimed);
    }
    let recovered: Awaited<ReturnType<typeof recoverApprovedDeviceLogin>>;
    try {
      recovered = await this.#awaitCurrent(
        context,
        recoverApprovedDeviceLogin(claimed.state, raw, this.#currentTime()),
      );
    } catch {
      await this.#clearExact(claimed.owner);
      return Object.freeze({ status: 'none' });
    }

    try {
      let activated: DeviceLoginActivationResult;
      const activationProgress: { stage: ObservedDeviceLoginActivationStage } = {
        stage: 'unreported',
      };
      const transitionOwner = deviceInteractiveOwner(claimed.owner);
      this.#activationOwner = transitionOwner;
      try {
        activated = await this.#awaitCurrent(context, this.deps.activate({
          state: claimed.state,
          userKey: recovered.userKey,
          serverUrl: claimed.owner.serverUrl,
          ...(twoFactor ? { twoFactor } : {}),
          ...(current.twoFactor?.forcePasswordReset
            ? { forcePasswordReset: true as const }
            : {}),
          ...(current.twoFactor?.masterPasswordPolicy
            ? { masterPasswordPolicy: current.twoFactor.masterPasswordPolicy }
            : {}),
          transitionOwner,
          assertTransitionOwnerCurrent: () => {
            this.#assertCurrent(context);
            if (!this.#activationOwner
                || !sameInteractiveTwoFactorOwner(this.#activationOwner, transitionOwner)) {
              throw coordinatorError('server_changed', 'The device login authorization changed.');
            }
          },
          reportActivationStage: (stage) => {
            activationProgress.stage = nextDeviceLoginActivationStage(
              activationProgress.stage,
              stage,
            );
          },
          ...(lifecycle ? {
            onGrantStarted: lifecycle.onGrantStarted,
            onGrantDispatched: lifecycle.onGrantDispatched,
          } : {}),
        }));
      } catch (error) {
        if (activationProgress.stage === 'pre_grant') {
          const released = await this.#releaseForRetry(claimed, current.twoFactor, context);
          if (lifecycle) throw error;
          return released;
        }
        if (activationProgress.stage === 'grant_rejected') {
          if (twoFactor) {
            const released = await this.#releaseForRetry(claimed, current.twoFactor, context);
            if (lifecycle) throw error;
            return released;
          }
          await this.#clearExact(claimed.owner);
          return Object.freeze({ status: 'none' });
        }
        if (error instanceof ApiHttpError && error.status === 400) {
          if (twoFactor) {
            const released = await this.#releaseForRetry(claimed, current.twoFactor, context);
            if (lifecycle) throw error;
            return released;
          }
          await this.#clearExact(claimed.owner);
          return Object.freeze({ status: 'none' });
        }
        if (lifecycle) {
          await this.#outcomeFromClaim(claimed);
          throw error;
        }
        return this.#outcomeFromClaim(claimed);
      } finally {
        if (this.#activationOwner
            && sameOwnerOrFalse(this.#activationOwner, transitionOwner)) {
          this.#activationOwner = undefined;
        }
      }

      if (activated.kind === 'unlocked') {
        await this.#clearExact(claimed.owner);
        await this.#stopRuntime(claimed.owner);
        return Object.freeze({ status: 'unlocked' });
      }
      if (activated.kind === 'restricted') {
        await this.#clearExact(claimed.owner);
        await this.#stopRuntime(claimed.owner);
        return Object.freeze({ status: 'restricted' });
      }
      if (activated.kind !== 'twoFactor') {
        await this.#clearExact(claimed.owner);
        return Object.freeze({ status: 'none' });
      }

      let providers: readonly number[];
      try {
        providers = canonicalProviders(activated.providers);
      } catch {
        await this.#clearExact(claimed.owner);
        throw coordinatorError('invalid_response', 'The two-factor challenge was invalid.');
      }
      const fido2 = providers.includes(FIDO2_PROVIDER)
        ? parseDeviceLoginFido2Challenge(
            activated.providerMetadata,
            claimed.owner.serverUrl,
          )
        : undefined;
      const duo = parseDeviceDuoSeeds(activated.providerMetadata, providers);
      const retainedProviders = providers.filter(
        (provider) => (provider !== FIDO2_PROVIDER || fido2 !== undefined)
          && (provider !== 2 && provider !== 6
            || duo.some((entry) => entry.provider === provider)),
      );
      const actionableProviders = retainedProviders.filter(
        (provider) => DIRECT_CODE_PROVIDERS.has(provider) || provider === FIDO2_PROVIDER
          || provider === 2 || provider === 6,
      );
      if (actionableProviders.length === 0) {
        await this.#clearExact(claimed.owner);
        return Object.freeze({
          status: 'two_factor_unsupported',
          providers,
          ...await this.#publicContext(current, context),
        });
      }
      const challenge: DeviceLoginStoredTwoFactorChallenge = Object.freeze({
        providers: Object.freeze(retainedProviders),
        ...(activated.token ? { token: activated.token } : {}),
        ...(fido2 ? { fido2 } : {}),
        ...(duo.length ? { duo } : {}),
        ...(activated.forcePasswordReset ? { forcePasswordReset: true as const } : {}),
        ...(activated.masterPasswordPolicy
          ? { masterPasswordPolicy: activated.masterPasswordPolicy }
          : {}),
      });
      let released: ActiveBoundSnapshot | undefined;
      try {
        released = await this.#awaitCurrent(
          context,
          this.deps.stateStore.release(claimed.owner, { twoFactor: challenge }),
        );
      } catch {
        return this.#outcomeFromClaim(claimed);
      }
      await clearAlarm(this.deps.alarms, pollAlarmName(claimed.owner));
      return released ? this.#publicTwoFactor(released) : this.#outcomeFromClaim(claimed);
    } finally {
      clearUserKey(recovered.userKey);
    }
  }

  async #releaseForRetry(
    claimed: ClaimedDeviceLoginStateSnapshot,
    twoFactor: DeviceLoginStoredTwoFactorChallenge | undefined,
    context: ServerContext,
  ): Promise<DeviceLoginCoordinatorResult> {
    try {
      const released = await this.#awaitCurrent(
        context,
        this.deps.stateStore.release(claimed.owner, {
          ...(twoFactor ? { twoFactor } : {}),
          retryRequired: true,
        }),
      );
      await clearAlarm(this.deps.alarms, pollAlarmName(claimed.owner));
      return released ? this.#publicRetry(released) : this.#outcomeFromClaim(claimed);
    } catch {
      return this.#outcomeFromClaim(claimed);
    }
  }

  async #outcomeFromClaim(
    claimed: ClaimedDeviceLoginStateSnapshot,
  ): Promise<DeviceLoginCoordinatorResult> {
    const outcome = await this.deps.stateStore
      .markOutcomeUnknown(claimed.owner)
      .catch(() => undefined);
    await clearAlarm(this.deps.alarms, pollAlarmName(claimed.owner));
    return outcome ? publicOutcomeUnknown(outcome) : Object.freeze({
      status: 'outcome_unknown',
      generation: claimed.owner.generation,
      serverOrigin: new URL(claimed.owner.serverUrl).origin,
      createdAt: claimed.state.createdAt,
      expiresAt: claimed.state.expiresAt,
      terminalAt: this.#currentTime(),
    });
  }

  async #outcomeFromActive(
    current: ActiveDeviceLoginStateSnapshot,
  ): Promise<DeviceLoginCoordinatorResult> {
    const outcome = await this.deps.stateStore
      .retireOutcomeUnknown(current.owner)
      .catch(() => undefined);
    await this.#stopRuntime(current.owner);
    return outcome ? publicOutcomeUnknown(outcome) : Object.freeze({
      status: 'outcome_unknown',
      generation: current.owner.generation,
      serverOrigin: new URL(current.owner.serverUrl).origin,
      createdAt: current.state.createdAt,
      expiresAt: current.state.expiresAt,
      terminalAt: this.#currentTime(),
    });
  }

  async #startNotifications(current: ActiveBoundSnapshot, context: ServerContext): Promise<void> {
    let notificationsUrl: string | undefined;
    try {
      if (this.deps.getNotificationsUrl) {
        notificationsUrl = await this.#awaitCurrent(
          context,
          Promise.resolve(this.deps.getNotificationsUrl(context.lease)),
        );
      }
      await this.#awaitCurrent(context, this.deps.notifications.start({
        serverUrl: current.owner.serverUrl,
        ...(notificationsUrl ? { notificationsUrl } : {}),
        requestId: current.state.requestId,
        expiresAt: current.state.expiresAt,
      }));
    } catch {
      // The independent authoritative poll remains available when SignalR is unavailable.
    }
    this.#notificationGeneration = current.owner.generation;
  }

  async #schedulePoll(current: ActiveBoundSnapshot, context: ServerContext): Promise<boolean> {
    return this.#scheduleWatchdog(current.owner, current.state.expiresAt, context);
  }

  async #scheduleWatchdog(
    owner: DeviceLoginStateOwner,
    expiresAt: number,
    context: ServerContext,
  ): Promise<boolean> {
    this.#assertCurrent(context);
    const now = this.#currentTime();
    const when = Math.min(expiresAt, now + DEVICE_LOGIN_STATUS_POLL_INTERVAL_MS);
    if (!Number.isSafeInteger(when) || when <= now) {
      await this.#clearExact(owner);
      await this.#stopRuntime(owner);
      return false;
    }
    try {
      await this.#awaitCurrent(context, Promise.all([
        Promise.resolve(this.deps.alarms.create(pollAlarmName(owner), { when })),
        Promise.resolve(this.deps.alarms.create(
          deadlineAlarmName(owner),
          { when: expiresAt },
        )),
      ]));
    } catch (error) {
      if (error instanceof DeviceLoginCoordinatorError) throw error;
      throw coordinatorError('request_failed', 'The device login watchdog could not be scheduled.');
    }
    return true;
  }

  async #handlePollAlarm(name: string): Promise<DeviceLoginCoordinatorResult | void> {
    const generation = parsePollAlarmGeneration(name);
    if (generation === undefined) return;
    const current = await this.deps.stateStore.read();
    if (
      current
      && !isOutcomeUnknown(current)
      && current.claimed
      && current.owner.generation === generation
    ) {
      const outcome = await this.deps.stateStore.markOutcomeUnknown(current.owner);
      await this.#stopRuntime(current.owner);
      return outcome ? publicOutcomeUnknown(outcome) : Object.freeze({ status: 'none' });
    }
    const active = activeBound(current);
    if (!active || active.owner.generation !== generation) {
      await this.#stopOrphanedRuntime(generation);
      await clearAlarm(this.deps.alarms, name);
      return active ? this.#resultWithoutAutomaticActivation(active) : resultForNonActive(current);
    }
    if (active.twoFactor || active.retryRequired) {
      await clearAlarm(this.deps.alarms, name);
      return this.#resultWithoutAutomaticActivation(active);
    }
    const context = await this.#contextFor(active.owner);
    if (!context) return this.#retireServerMismatch(active);
    if (!await this.#schedulePoll(active, context)) return Object.freeze({ status: 'expired' });
    const observed = await this.#observeOnce(active, context);
    if (observed.kind === 'settled') return observed.result;
    return this.#publicPending(active, context);
  }

  async #handleDeadlineAlarm(name: string): Promise<DeviceLoginCoordinatorResult | void> {
    const generation = parseAlarmGeneration(name, DEVICE_LOGIN_DEADLINE_ALARM_PREFIX);
    if (generation === undefined) return;
    const current = await this.deps.stateStore.read();
    if (!current || current.owner.generation !== generation) {
      await this.#stopOrphanedRuntime(generation);
      await clearAlarm(this.deps.alarms, name);
      return resultForNonActive(current);
    }
    if (isOutcomeUnknown(current)) return publicOutcomeUnknown(current);
    if (!current.claimed && current.state.phase === 'pending') {
      const outcome = await this.deps.stateStore.retireOutcomeUnknown(current.owner);
      return outcome ? publicOutcomeUnknown(outcome) : Object.freeze({ status: 'none' });
    }
    const expiresAt = current.state.expiresAt;
    if (this.#currentTime() < expiresAt) {
      await Promise.resolve(this.deps.alarms.create(name, { when: expiresAt })).catch(() => undefined);
      return current.claimed
        ? Object.freeze({ status: 'none' })
        : this.#resultWithoutAutomaticActivation(current as ActiveBoundSnapshot);
    }
    await this.#clearExact(current.owner);
    await this.#stopRuntime(current.owner);
    return Object.freeze({ status: 'expired' });
  }

  async #prearmPoll(name: string): Promise<void> {
    if (parsePollAlarmGeneration(name) === undefined) return;
    const when = this.#currentTime() + DEVICE_LOGIN_STATUS_POLL_INTERVAL_MS;
    if (!Number.isSafeInteger(when)) return;
    try {
      await this.deps.alarms.create(name, { when });
    } catch {
      // The durable deadline alarm remains; the serialized handler retries the bounded watchdog.
    }
  }

  async #publicPending(
    current: ActiveBoundSnapshot,
    context: ServerContext,
  ): Promise<DeviceLoginCoordinatorResult> {
    const publicContext = await this.#publicContext(current, context);
    this.#cancellableOwner = Object.freeze({ ...current.owner });
    return Object.freeze({ status: 'pending', ...publicContext });
  }

  async #publicTwoFactor(current: ActiveBoundSnapshot): Promise<DeviceLoginCoordinatorResult> {
    const context = await this.#contextFor(current.owner);
    if (!context) return this.#retireServerMismatch(current);
    try {
      if (!await this.#scheduleExpiryAlarm(current, context)) {
        return Object.freeze({ status: 'expired' });
      }
    } catch {
      return this.#outcomeFromActive(current);
    }
    const publicContext = await this.#publicContext(current, context);
    this.#cancellableOwner = Object.freeze({ ...current.owner });
    return Object.freeze({
      status: 'two_factor',
      providers: Object.freeze([...(current.twoFactor?.providers ?? [])]),
      ...(current.twoFactor?.fido2
        ? {
            fido2: Object.freeze({
              owner: deviceInteractiveOwner(current.owner),
            }),
          }
        : {}),
      ...publicContext,
    });
  }

  async #publicRetry(current: ActiveBoundSnapshot): Promise<DeviceLoginCoordinatorResult> {
    const context = await this.#contextFor(current.owner);
    if (!context) return this.#retireServerMismatch(current);
    try {
      if (!await this.#scheduleExpiryAlarm(current, context)) {
        return Object.freeze({ status: 'expired' });
      }
    } catch {
      return this.#outcomeFromActive(current);
    }
    const publicContext = await this.#publicContext(current, context);
    this.#cancellableOwner = Object.freeze({ ...current.owner });
    return Object.freeze({
      status: 'retry_required',
      ...(current.twoFactor
        ? { providers: Object.freeze([...current.twoFactor.providers]) }
        : {}),
      ...(current.twoFactor?.fido2
        ? {
            fido2: Object.freeze({
              owner: deviceInteractiveOwner(current.owner),
            }),
          }
        : {}),
      ...publicContext,
    });
  }

  async #scheduleExpiryAlarm(
    current: ActiveBoundSnapshot,
    context: ServerContext,
  ): Promise<boolean> {
    const now = this.#currentTime();
    if (now >= current.state.expiresAt) {
      await this.#clearExact(current.owner);
      return false;
    }
    try {
      await this.#awaitCurrent(
        context,
        Promise.resolve(this.deps.alarms.create(
          deadlineAlarmName(current.owner),
          { when: current.state.expiresAt },
        )),
      );
    } catch (error) {
      if (error instanceof DeviceLoginCoordinatorError) throw error;
      throw coordinatorError('request_failed', 'The device login deadline could not be scheduled.');
    }
    return true;
  }

  async #publicContext(
    current: DeviceLoginStateSnapshot & { readonly state: DeviceLoginBoundState },
    context: ServerContext,
  ): Promise<DeviceLoginPublicContext> {
    const publicKey = base64ToBytes(current.state.publicKey);
    let fingerprint: string;
    try {
      fingerprint = await this.#awaitCurrent(
        context,
        deriveDeviceLoginFingerprint(current.state.email, publicKey, FINGERPRINT_WORDLIST),
      );
    } finally {
      publicKey.fill(0);
    }
    return Object.freeze({
      generation: current.owner.generation,
      fingerprint,
      serverOrigin: new URL(current.owner.serverUrl).origin,
      email: current.state.email,
      deviceName: current.state.device.name,
      expiresAt: current.state.expiresAt,
    });
  }

  #resultWithoutAutomaticActivation(current: ActiveBoundSnapshot): Promise<DeviceLoginCoordinatorResult> {
    return current.twoFactor && !current.retryRequired
      ? this.#publicTwoFactor(current)
      : this.#publicRetry(current);
  }

  async #retireServerMismatch(
    current: DeviceLoginStateSnapshot,
  ): Promise<DeviceLoginCoordinatorResult> {
    await this.#clearExact(current.owner);
    await this.#stopRuntime(current.owner);
    return Object.freeze({ status: 'none' });
  }

  async #contextFor(owner: DeviceLoginStateOwner): Promise<ServerContext | undefined> {
    const remembered = this.#ceremonyLease;
    if (remembered) {
      if (remembered.serverUrl !== owner.serverUrl) return undefined;
      try {
        this.#assertLease(remembered);
      } catch {
        return undefined;
      }
      return this.#contextFromLease(remembered);
    }
    let context: ServerContext;
    try {
      context = this.#captureServer();
    } catch {
      return undefined;
    }
    if (context.lease.serverUrl !== owner.serverUrl) return undefined;
    this.#ceremonyLease = context.lease;
    return context;
  }

  #captureServer(): ServerContext {
    let lease: ServerLease;
    try {
      lease = this.deps.serverGate.captureServer();
      this.deps.serverGate.assertServer(lease);
    } catch {
      throw coordinatorError('server_changed', 'No current device login server is available.');
    }
    return this.#contextFromLease(lease);
  }

  #contextFromLease(lease: ServerLease): ServerContext {
    const authorizationEpoch = this.#authorizationEpoch;
    const api = this.deps.api
      .forServer(lease.serverUrl)
      .withRequestGuard(() => {
        this.#assertAuthorizationEpoch(authorizationEpoch);
        this.#assertLease(lease);
      });
    return Object.freeze({ lease, api, authorizationEpoch });
  }

  #assertLease(lease: ServerLease): void {
    try {
      this.deps.serverGate.assertServer(lease);
    } catch {
      throw coordinatorError('server_changed', 'The configured server changed.');
    }
  }

  #assertCurrent(context: ServerContext): void {
    this.#assertAuthorizationEpoch(context.authorizationEpoch);
    this.#assertLease(context.lease);
  }

  #assertAuthorizationEpoch(epoch: number): void {
    if (epoch !== this.#authorizationEpoch) {
      throw coordinatorError('server_changed', 'The device login authorization changed.');
    }
  }

  async #awaitCurrent<T>(context: ServerContext, promise: PromiseLike<T>): Promise<T> {
    this.#assertCurrent(context);
    const result = await promise;
    this.#assertCurrent(context);
    return result;
  }

  async #clearExact(owner: DeviceLoginStateOwner): Promise<void> {
    if (this.#cancellableOwner && sameCancellationLineage(owner, this.#cancellableOwner)) {
      this.#cancellableOwner = undefined;
    }
    this.#rememberConnectorCleanup(this.#takeInteractiveRuntime(owner));
    await this.deps.stateStore.clear(owner).catch(() => false);
    await Promise.all([
      clearAlarm(this.deps.alarms, pollAlarmName(owner)),
      clearAlarm(this.deps.alarms, deadlineAlarmName(owner)),
      this.#flushConnectorCleanup(),
    ]);
  }

  async #stopRuntime(owner: DeviceLoginStateOwner): Promise<void> {
    this.#rememberConnectorCleanup(this.#takeInteractiveRuntime(owner));
    if (this.#notificationGeneration === owner.generation) this.#notificationGeneration = undefined;
    await Promise.all([
      this.deps.notifications.stop().catch(() => undefined),
      clearAlarm(this.deps.alarms, pollAlarmName(owner)),
      clearAlarm(this.deps.alarms, deadlineAlarmName(owner)),
      this.#flushConnectorCleanup(),
    ]);
  }

  async #stopOrphanedRuntime(generation?: number): Promise<void> {
    const runtime = this.#interactiveRuntime;
    if (runtime && (generation === undefined || runtime.owner.generation === generation)) {
      await this.#stopRuntime({
        generation: runtime.owner.generation,
        serverUrl: runtime.owner.serverUrl,
        requestId: runtime.owner.bindingId,
      });
      return;
    }
    await this.#flushConnectorCleanup();
    if (generation === undefined || this.#notificationGeneration === generation) {
      this.#notificationGeneration = undefined;
      await this.deps.notifications.stop().catch(() => undefined);
    }
  }

  #takeInteractiveRuntime(
    owner?: DeviceLoginStateOwner,
  ): InteractiveTwoFactorConnectorCaller | undefined {
    const current = this.#interactiveRuntime;
    if (!current || (owner && !sameDeviceAndInteractiveOwner(owner, current.owner))) return undefined;
    this.#interactiveRuntime = undefined;
    return current.tabId !== undefined && current.documentId
      ? Object.freeze({
          tabId: current.tabId,
          documentId: current.documentId,
          url: current.expectedUrl,
        })
      : undefined;
  }

  #rememberConnectorCleanup(document: InteractiveTwoFactorConnectorCaller | undefined): void {
    if (document) this.#connectorPendingCleanup = document;
  }

  async #flushConnectorCleanup(): Promise<void> {
    const document = this.#connectorPendingCleanup;
    this.#connectorPendingCleanup = undefined;
    if (!document || !this.deps.closeInteractiveTwoFactorConnector) return;
    await Promise.resolve(this.deps.closeInteractiveTwoFactorConnector(document)).catch(() => undefined);
  }

  #invalidateAuthorization(): void {
    this.#authorizationEpoch += 1;
    this.#activationOwner = undefined;
    this.#ceremonyLease = undefined;
    this.#rememberConnectorCleanup(this.#takeInteractiveRuntime());
    this.#notificationGeneration = undefined;
    this.#cancellableOwner = undefined;
  }

  #currentTime(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw coordinatorError('invalid_input', 'The device login clock is invalid.');
    }
    return now;
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#tail.then(operation, operation);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

function deviceInteractiveOwner(owner: DeviceLoginStateOwner): InteractiveTwoFactorOwner {
  if (!owner.requestId) {
    throw coordinatorError('invalid_input', 'The device-login request is not server-bound.');
  }
  return createInteractiveTwoFactorOwner({
    flow: 'deviceLogin',
    generation: owner.generation,
    serverUrl: owner.serverUrl,
    bindingId: owner.requestId,
  });
}

function parseDeviceInteractiveOwner(owner: InteractiveTwoFactorOwner): InteractiveTwoFactorOwner {
  let parsed: InteractiveTwoFactorOwner;
  try {
    parsed = createInteractiveTwoFactorOwner(owner);
  } catch {
    throw coordinatorError('invalid_input', 'The interactive challenge owner is invalid.');
  }
  if (parsed.flow !== 'deviceLogin') {
    throw coordinatorError('invalid_input', 'The interactive challenge has the wrong owner.');
  }
  return parsed;
}

function parseConnectorDocumentId(value: unknown): string {
  try {
    return parseInteractiveTwoFactorDocumentId(value);
  } catch {
    throw coordinatorError('invalid_input', 'The security-key connector document is invalid.');
  }
}

function sameDeviceAndInteractiveOwner(
  owner: DeviceLoginStateOwner,
  interactive: InteractiveTwoFactorOwner,
): boolean {
  if (!owner.requestId) return false;
  try {
    return sameInteractiveTwoFactorOwner(deviceInteractiveOwner(owner), interactive);
  } catch {
    return false;
  }
}

function sameOwnerOrFalse(
  left: InteractiveTwoFactorOwner,
  right: InteractiveTwoFactorOwner,
): boolean {
  try {
    return sameInteractiveTwoFactorOwner(left, right);
  } catch {
    return false;
  }
}

function sameCancellationLineage(
  current: DeviceLoginStateOwner,
  visible: DeviceLoginStateOwner,
): boolean {
  return current.serverUrl === visible.serverUrl
    && (
      current.requestId === undefined
      || visible.requestId === undefined
      || current.requestId === visible.requestId
    );
}

function parseDeviceLoginFido2Challenge(
  providerMetadata: Readonly<Record<string, unknown>> | undefined,
  serverUrl: string,
): DeviceLoginStoredFido2Challenge | undefined {
  if (!providerMetadata) return undefined;
  try {
    const connectorUrl = interactiveTwoFactorConnectorUrl(serverUrl);
    const connector = new URL(connectorUrl);
    const request = parseFido2TwoFactorRequest(providerMetadata, {
      origin: connector.origin,
      rpId: connector.hostname,
    });
    return Object.freeze({
      connectorData: request.connectorData,
      connectorUrl,
    });
  } catch {
    return undefined;
  }
}

function parseDeviceDuoSeeds(
  providerMetadata: Readonly<Record<string, unknown>> | undefined,
  providers: readonly number[],
): readonly DuoProviderSeed[] {
  if (!providerMetadata) return Object.freeze([]);
  const seeds: DuoProviderSeed[] = [];
  for (const provider of [2, 6] as const) {
    if (!providers.includes(provider)) continue;
    try {
      seeds.push(extractDuoProviderSeed(providerMetadata, provider));
    } catch {
      // Legacy Signature or malformed modern metadata remains unavailable.
    }
  }
  return Object.freeze(seeds);
}

function restoreDeviceLoginFido2Request(
  challenge: DeviceLoginStoredFido2Challenge,
  serverUrl: string,
): Fido2TwoFactorRequest {
  const connectorUrl = interactiveTwoFactorConnectorUrl(serverUrl);
  if (challenge.connectorUrl !== connectorUrl) {
    throw coordinatorError('invalid_input', 'The security-key connector changed.');
  }
  let metadata: unknown;
  try {
    metadata = JSON.parse(challenge.connectorData) as unknown;
  } catch {
    throw coordinatorError('invalid_input', 'The security-key challenge is invalid.');
  }
  const connector = new URL(connectorUrl);
  try {
    const request = parseFido2TwoFactorRequest(metadata, {
      origin: connector.origin,
      rpId: connector.hostname,
    });
    if (request.connectorData !== challenge.connectorData) {
      throw new Error('non-canonical challenge');
    }
    return request;
  } catch {
    throw coordinatorError('invalid_input', 'The security-key challenge is invalid.');
  }
}

type ActiveBoundSnapshot = ActiveDeviceLoginBoundStateSnapshot;

function activeBound(
  value: DeviceLoginStateReadResult | undefined,
): ActiveBoundSnapshot | undefined {
  return value
    && !isOutcomeUnknown(value)
    && !value.claimed
    && value.state.phase === 'bound'
    ? value as ActiveBoundSnapshot
    : undefined;
}

function isOutcomeUnknown(
  value: DeviceLoginStateReadResult,
): value is DeviceLoginOutcomeUnknownSnapshot {
  return 'status' in value && value.status === 'outcome_unknown';
}

function publicOutcomeUnknown(
  value: DeviceLoginOutcomeUnknownSnapshot,
): DeviceLoginCoordinatorResult {
  return Object.freeze({
    status: 'outcome_unknown',
    generation: value.owner.generation,
    serverOrigin: new URL(value.owner.serverUrl).origin,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    terminalAt: value.terminalAt,
  });
}

function resultForNonActive(
  value: DeviceLoginStateReadResult | undefined,
): DeviceLoginCoordinatorResult {
  return value && isOutcomeUnknown(value)
    ? publicOutcomeUnknown(value)
    : Object.freeze({ status: 'none' });
}

function classifyResponse(
  state: DeviceLoginBoundState,
  raw: unknown,
  now: number,
): ResponseClassification {
  const response = parseAuthRequestResponse(raw, now);
  if (
    response.id !== state.requestId
    || response.publicKey !== state.publicKey
    || response.requestDeviceIdentifier !== state.device.identifier
    || response.requestDeviceTypeValue !== state.device.type
    || response.creationDate !== state.serverCreationDate
  ) throw new Error('Device login response binding failed');
  if (response.expired || now >= state.expiresAt) {
    throw new Error('Device login response expired');
  }
  if (!response.answered) {
    if (response.requestApproved
        || response.key !== undefined
        || response.masterPasswordHash !== undefined) {
      throw new Error('Device login pending response is inconsistent');
    }
    return { kind: 'pending' };
  }
  if (!response.requestApproved) {
    if (response.key !== undefined || response.masterPasswordHash !== undefined) {
      throw new Error('Device login denial contains key material');
    }
    return { kind: 'denied' };
  }
  return { kind: 'approved', raw };
}

function canonicalProviders(values: readonly number[]): readonly number[] {
  const providers = [...new Set(values)];
  if (providers.length === 0
      || providers.some((provider) => (
        !Number.isInteger(provider) || provider < 0 || provider > 255
      ))) {
    throw coordinatorError('invalid_response', 'The two-factor challenge was invalid.');
  }
  return Object.freeze(providers.sort((left, right) => left - right));
}

function parseTwoFactorSubmission(input: {
  readonly generation: number;
  readonly provider: number;
  readonly code: string;
  readonly remember?: boolean;
}): {
  readonly generation: number;
  readonly provider: number;
  readonly code: string;
  readonly remember?: boolean;
} {
  if (!isPlainRecord(input)) {
    throw coordinatorError('invalid_input', 'The two-factor response is invalid.');
  }
  const allowed = new Set(['generation', 'provider', 'code', 'remember']);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    throw coordinatorError('invalid_input', 'The two-factor response is invalid.');
  }
  const code = typeof input.code === 'string' ? input.code.trim() : '';
  assertExpectedGeneration(input.generation);
  if (!Number.isInteger(input.provider)
      || input.provider < 0
      || input.provider > 255
      || code.length === 0
      || code.length > MAX_TWO_FACTOR_CODE_LENGTH
      || (input.remember !== undefined && typeof input.remember !== 'boolean')) {
    throw coordinatorError('invalid_input', 'The two-factor response is invalid.');
  }
  return Object.freeze({
    generation: input.generation,
    provider: input.provider,
    code,
    ...(input.remember !== undefined ? { remember: input.remember } : {}),
  });
}

function assertExpectedGeneration(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw coordinatorError('invalid_input', 'The device-login owner generation is invalid.');
  }
}

function assertCurrentGeneration(
  current: DeviceLoginStateReadResult | undefined,
  expectedGeneration: number,
): void {
  if (!current || current.owner.generation !== expectedGeneration) {
    throw coordinatorError('invalid_input', 'The device-login request owner changed.');
  }
}

function pollAlarmName(owner: Pick<DeviceLoginStateOwner, 'generation'>): string {
  return `${DEVICE_LOGIN_STATUS_ALARM_PREFIX}${owner.generation}`;
}

function deadlineAlarmName(owner: Pick<DeviceLoginStateOwner, 'generation'>): string {
  return `${DEVICE_LOGIN_DEADLINE_ALARM_PREFIX}${owner.generation}`;
}

function parsePollAlarmGeneration(name: string): number | undefined {
  return parseAlarmGeneration(name, DEVICE_LOGIN_STATUS_ALARM_PREFIX);
}

function parseAlarmGeneration(name: string, prefix: string): number | undefined {
  const value = name.slice(prefix.length);
  if (!/^[1-9]\d*$/u.test(value)) return undefined;
  const generation = Number(value);
  return Number.isSafeInteger(generation) ? generation : undefined;
}

async function clearAlarm(
  alarms: VaultNotificationsAlarmScheduler,
  name: string,
): Promise<void> {
  try {
    await alarms.clear(name);
  } catch {
    // Alarm cleanup is idempotent and never exposes request identity through diagnostics.
  }
}

function clearUserKey(key: SymmetricKey): void {
  key.encKey.fill(0);
  key.macKey.fill(0);
}

function isDefiniteClientFailure(error: unknown): error is ApiHttpError {
  return error instanceof ApiHttpError
    && error.status >= 400
    && error.status < 500
    && error.status !== 408
    && error.status !== 429;
}

type ObservedDeviceLoginActivationStage = DeviceLoginActivationStage | 'unreported' | 'invalid';

function nextDeviceLoginActivationStage(
  current: ObservedDeviceLoginActivationStage,
  next: DeviceLoginActivationStage,
): ObservedDeviceLoginActivationStage {
  if (current === 'unreported' && next === 'pre_grant') return next;
  if (current === 'pre_grant' && next === 'grant_started') return next;
  if (current === 'grant_started' && next === 'grant_rejected') return next;
  if (current === 'grant_rejected' && next === 'grant_started') return next;
  return 'invalid';
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(descriptor?.enumerable && 'value' in descriptor && descriptor.value !== undefined);
  });
}

function coordinatorError(
  code: DeviceLoginCoordinatorErrorCode,
  message: string,
): DeviceLoginCoordinatorError {
  return new DeviceLoginCoordinatorError(code, message);
}
