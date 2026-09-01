import type { ApiClient } from '../core/api/client.js';
import { base64ToBytes, base64UrlToBytes, bytesToBase64Url, constantTimeEqual, utf8ToBytes } from '../core/crypto/encoding.js';
import { hmacSha256 } from '../core/crypto/primitives.js';
import type { SymmetricKey } from '../core/crypto/keys.js';
import { AppError } from '../core/errors.js';
import type { AccountLease, AccountLeaseGate } from '../core/session/account-gate.js';
import {
  type DeviceLoginApprovalBody,
  type DeviceLoginApprovalContext,
  type DeviceLoginApprovalView,
  type DeviceLoginRejectionBody,
  inspectPendingDeviceLoginRequest,
  prepareDeviceLoginApproval,
  prepareDeviceLoginRejection,
} from '../core/session/device-login-approval.js';
import {
  DEVICE_LOGIN_REQUEST_TTL_MS,
  parseAuthRequestResponse,
  type ParsedAuthRequestResponse,
} from '../core/session/device-login.js';
import type { AuthService } from '../core/session/auth-service.js';
import type {
  ActiveAuth,
  SessionLease,
  SessionLeaseGate,
  SessionManager,
} from '../core/session/session-manager.js';

const BINDING_VERSION = 1 as const;
const BINDING_KEY_BYTES = 32;
const BINDING_NONCE_BYTES = 16;
const SHA256_BASE64URL_LENGTH = 43;
const NONCE_BASE64URL_LENGTH = 22;
const MAX_DEVICE_IDENTIFIER_LENGTH = 255;
const MAX_CONSUMED_BINDINGS = 4_096;
const MAX_CLOCK_SKEW_MS = 5 * 60_000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const BINDING_FIELDS = new Set([
  'version',
  'requestId',
  'publicKeyDigest',
  'requestDeviceIdentifier',
  'creationDate',
  'requestDeviceTypeValue',
  'nonce',
  'proof',
]);

export interface DeviceLoginDecisionBinding {
  readonly version: typeof BINDING_VERSION;
  readonly requestId: string;
  readonly publicKeyDigest: string;
  readonly requestDeviceIdentifier: string;
  readonly creationDate: string;
  readonly requestDeviceTypeValue: number;
  readonly nonce: string;
  readonly proof: string;
}

export interface BoundDeviceLoginApprovalView {
  readonly view: DeviceLoginApprovalView;
  readonly decisionBinding: DeviceLoginDecisionBinding;
}

export interface DeviceLoginDecisionReceipt {
  readonly requestId: string;
  readonly requestApproved: boolean;
  readonly responseDate: string;
}

/** Minimal locked-safe projection used only for badge and system-notification discovery. */
export interface DeviceLoginApprovalDiscovery {
  readonly requestId: string;
  readonly expiresAt: number;
}

export interface DeviceLoginApprovalServiceDeps {
  readonly api: Pick<ApiClient, 'forServer'>;
  readonly session: Pick<SessionManager, 'getActiveAuth' | 'loadUserKey'>;
  readonly auth: Pick<AuthService, 'getAccessToken' | 'getAccountAccessToken'>;
  readonly sessionGate: SessionLeaseGate;
  readonly accountGate: Pick<AccountLeaseGate, 'capture' | 'assert'>;
  readonly now?: () => number;
}

interface ApprovalOperation {
  readonly accountLease: AccountLease;
  readonly sessionLease: SessionLease;
  readonly api: ApiClient;
}

interface ApprovalDiscoveryOperation {
  readonly accountLease: AccountLease;
  readonly api: ApiClient;
}

interface ApprovalSecurityContext extends DeviceLoginApprovalContext {
  readonly accessToken: string;
  readonly sessionBindingId: string;
}

interface DecisionSnapshot {
  readonly requestId: string;
  readonly publicKey: string;
  readonly publicKeyDigest: string;
  readonly requestDeviceIdentifier: string;
  readonly creationDate: string;
  readonly requestDeviceTypeValue: number;
}

interface ValidatedPendingRequest {
  readonly raw: unknown;
  readonly parsed: ParsedAuthRequestResponse;
  readonly view: DeviceLoginApprovalView;
  readonly snapshot: DecisionSnapshot;
}

/**
 * Lease-bound approving-device workflow. Bindings are authenticated by a process-local key and are
 * single-use; a service-worker restart deliberately invalidates every outstanding confirmation.
 */
export class DeviceLoginApprovalService {
  private readonly now: () => number;
  private readonly bindingKey = randomBytes(BINDING_KEY_BYTES);
  private readonly consumedBindings = new Map<string, number>();
  private readonly activeRequestClaims = new Set<string>();
  private readonly writtenRequestClaims = new Map<string, number>();

  constructor(private readonly deps: DeviceLoginApprovalServiceDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  list(): Promise<readonly BoundDeviceLoginApprovalView[]> {
    const operation = this.captureOperation();
    return this.listForOperation(operation);
  }

  /**
   * Discover pending approvals while the active account is locked. This path deliberately has no
   * SessionLease, active-session binding, decision binding, device identifier, or UserKey access.
   */
  async discover(): Promise<readonly DeviceLoginApprovalDiscovery[]> {
    const operation = this.captureDiscoveryOperation();
    const assertCurrent = (): void => this.deps.accountGate.assert(operation.accountLease);
    let accessToken: string;
    try {
      accessToken = await this.deps.auth.getAccountAccessToken(operation.accountLease);
    } catch {
      assertCurrent();
      throw contextUnavailable();
    }
    assertCurrent();
    let rawRequests: unknown[];
    try {
      rawRequests = await operation.api.listPendingAuthRequests(accessToken);
    } catch {
      assertCurrent();
      throw new AppError('error', 'Pending device login requests could not be loaded.');
    }
    assertCurrent();
    if (!Array.isArray(rawRequests) || rawRequests.length > MAX_CONSUMED_BINDINGS) {
      throw new AppError('error', 'Pending device login requests are invalid.');
    }
    const now = this.readNow();
    const unique = new Map<string, DeviceLoginApprovalDiscovery>();
    const conflicts = new Set<string>();
    for (const raw of rawRequests) {
      try {
        const parsed = parseAuthRequestResponse(raw, now);
        if (parsed.requestApproved || parsed.answered || parsed.expired
            || parsed.key !== undefined || parsed.masterPasswordHash !== undefined
            || parsed.creationTime > now + MAX_CLOCK_SKEW_MS) continue;
        const expiresAt = parsed.creationTime + DEVICE_LOGIN_REQUEST_TTL_MS;
        if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) continue;
        const candidate = Object.freeze({ requestId: parsed.id, expiresAt });
        const previous = unique.get(candidate.requestId);
        if (previous && previous.expiresAt !== candidate.expiresAt) {
          conflicts.add(candidate.requestId);
          unique.delete(candidate.requestId);
        } else if (!conflicts.has(candidate.requestId)) {
          unique.set(candidate.requestId, candidate);
        }
      } catch {
        // A malformed entry cannot suppress other valid minimal discovery results.
      }
      assertCurrent();
    }
    assertCurrent();
    return Object.freeze([...unique.values()].sort((left, right) => (
      left.expiresAt - right.expiresAt || left.requestId.localeCompare(right.requestId)
    )));
  }

  get(requestId: unknown): Promise<BoundDeviceLoginApprovalView> {
    const operation = this.captureOperation();
    return this.getForOperation(operation, requestId);
  }

  approve(binding: unknown): Promise<DeviceLoginDecisionReceipt> {
    const operation = this.captureOperation();
    return this.decide(operation, binding, true);
  }

  deny(binding: unknown): Promise<DeviceLoginDecisionReceipt> {
    const operation = this.captureOperation();
    return this.decide(operation, binding, false);
  }

  private captureOperation(): ApprovalOperation {
    const accountLease = this.deps.accountGate.capture();
    const sessionLease = this.deps.sessionGate.capture();
    const assertCurrent = (): void => this.assertOperation({ accountLease, sessionLease });
    assertCurrent();
    let api: ApiClient;
    try {
      api = this.deps.api
        .forServer(accountLease.serverUrl)
        .withRequestGuard(assertCurrent);
    } catch {
      assertCurrent();
      throw contextUnavailable();
    }
    assertCurrent();
    return Object.freeze({ accountLease, sessionLease, api });
  }

  private captureDiscoveryOperation(): ApprovalDiscoveryOperation {
    const accountLease = this.deps.accountGate.capture();
    const assertCurrent = (): void => this.deps.accountGate.assert(accountLease);
    assertCurrent();
    let api: ApiClient;
    try {
      api = this.deps.api.forServer(accountLease.serverUrl).withRequestGuard(assertCurrent);
    } catch {
      assertCurrent();
      throw contextUnavailable();
    }
    assertCurrent();
    return Object.freeze({ accountLease, api });
  }

  private assertOperation(
    operation: Pick<ApprovalOperation, 'accountLease' | 'sessionLease'>,
  ): void {
    this.deps.accountGate.assert(operation.accountLease);
    this.deps.sessionGate.assert(operation.sessionLease);
  }

  private async listForOperation(
    operation: ApprovalOperation,
  ): Promise<readonly BoundDeviceLoginApprovalView[]> {
    const security = await this.readSecurityContext(operation);
    this.assertOperation(operation);
    let rawRequests: unknown[];
    try {
      rawRequests = await operation.api.listPendingAuthRequests(security.accessToken);
    } catch {
      this.assertOperation(operation);
      throw new AppError('error', 'Pending device login requests could not be loaded.');
    }
    this.assertOperation(operation);

    const output: BoundDeviceLoginApprovalView[] = [];
    for (const raw of rawRequests) {
      try {
        const request = await this.validatePending(raw, security, operation);
        this.assertOperation(operation);
        const decisionBinding = await this.issueBinding(request.snapshot, security, operation);
        this.assertOperation(operation);
        output.push(Object.freeze({ view: request.view, decisionBinding }));
      } catch {
        // One malformed entry cannot expose its raw contents or suppress other valid requests.
        this.assertOperation(operation);
      }
    }
    this.assertOperation(operation);
    return Object.freeze(output);
  }

  private async getForOperation(
    operation: ApprovalOperation,
    requestId: unknown,
  ): Promise<BoundDeviceLoginApprovalView> {
    const id = requireRequestId(requestId);
    const security = await this.readSecurityContext(operation);
    this.assertOperation(operation);
    const raw = await this.fetchPendingRequest(operation, security.accessToken, id);
    this.assertOperation(operation);
    let request: ValidatedPendingRequest;
    try {
      request = await this.validatePending(raw, security, operation);
    } catch {
      this.assertOperation(operation);
      throw invalidPendingRequest();
    }
    this.assertOperation(operation);
    const decisionBinding = await this.issueBinding(request.snapshot, security, operation);
    this.assertOperation(operation);
    return Object.freeze({ view: request.view, decisionBinding });
  }

  private async decide(
    operation: ApprovalOperation,
    rawBinding: unknown,
    approve: boolean,
  ): Promise<DeviceLoginDecisionReceipt> {
    const binding = parseDecisionBinding(rawBinding);
    const security = await this.readSecurityContext(operation);
    this.assertOperation(operation);
    await this.assertAuthenticBinding(binding, security, operation);
    this.assertOperation(operation);
    const expiresAt = this.consumeBinding(binding);
    const claim = this.claimRequest(binding, operation, expiresAt);
    let writeStarted = false;
    try {
      const raw = await this.fetchPendingRequest(
        operation,
        security.accessToken,
        binding.requestId,
      );
      this.assertOperation(operation);
      let latest: ValidatedPendingRequest;
      try {
        latest = await this.validatePending(raw, security, operation);
      } catch {
        this.assertOperation(operation);
        throw invalidPendingRequest();
      }
      this.assertOperation(operation);
      assertBindingMatchesSnapshot(binding, latest.snapshot);

      const userKey = approve
        ? await this.loadApprovalUserKey(operation, security)
        : undefined;
      this.assertOperation(operation);
      let prepared: {
        readonly body: DeviceLoginApprovalBody | DeviceLoginRejectionBody;
      };
      try {
        prepared = approve
          ? await prepareDeviceLoginApproval(raw, {
              accountEmail: security.accountEmail,
              approvalDeviceIdentifier: security.approvalDeviceIdentifier,
              userKey: userKey!,
            }, this.readNow())
          : await prepareDeviceLoginRejection(raw, security, this.readNow());
      } catch {
        this.assertOperation(operation);
        throw invalidPendingRequest();
      }
      this.assertOperation(operation);

      // From this point on, any failure is conservatively outcome-unknown. There is intentionally no
      // retry path: the PUT may have committed before a response, parser, or lease failure surfaced.
      this.assertOperation(operation);
      let rawResponse: unknown;
      try {
        writeStarted = true;
        rawResponse = await operation.api.updateAuthRequest(
          security.accessToken,
          binding.requestId,
          prepared.body,
        );
        this.assertOperation(operation);
        return validateDecisionResponse(
          rawResponse,
          latest.snapshot,
          approve,
          approve ? (prepared.body as DeviceLoginApprovalBody).key : undefined,
          this.readNow(),
        );
      } catch {
        throw decisionOutcomeUnknown();
      }
    } finally {
      this.activeRequestClaims.delete(claim);
      if (writeStarted) this.writtenRequestClaims.set(claim, expiresAt);
    }
  }

  private async readSecurityContext(
    operation: ApprovalOperation,
  ): Promise<ApprovalSecurityContext> {
    let initialAuth: ActiveAuth | undefined;
    try {
      initialAuth = await this.deps.session.getActiveAuth();
    } catch {
      this.assertOperation(operation);
      throw contextUnavailable();
    }
    this.assertOperation(operation);
    const sessionBindingId = requireBoundActiveAuth(initialAuth, operation.accountLease);

    let accessToken: string;
    try {
      accessToken = await this.deps.auth.getAccessToken(
        operation.sessionLease,
        operation.accountLease,
      );
    } catch {
      this.assertOperation(operation);
      throw contextUnavailable();
    }
    this.assertOperation(operation);

    let approvalDeviceIdentifier: string;
    try {
      approvalDeviceIdentifier = await operation.api.getDeviceIdentifier();
    } catch {
      this.assertOperation(operation);
      throw contextUnavailable();
    }
    this.assertOperation(operation);
    assertDeviceIdentifier(approvalDeviceIdentifier);

    let finalAuth: ActiveAuth | undefined;
    try {
      finalAuth = await this.deps.session.getActiveAuth();
    } catch {
      this.assertOperation(operation);
      throw contextUnavailable();
    }
    this.assertOperation(operation);
    if (
      !finalAuth
      || finalAuth.email !== operation.accountLease.accountIdentity
      || finalAuth.email !== initialAuth?.email
      || finalAuth.sessionBindingId !== sessionBindingId
      || finalAuth.accessToken !== accessToken
    ) {
      throw contextUnavailable();
    }

    return Object.freeze({
      accountEmail: finalAuth.email,
      approvalDeviceIdentifier,
      accessToken,
      sessionBindingId,
    });
  }

  private async loadApprovalUserKey(
    operation: ApprovalOperation,
    security: ApprovalSecurityContext,
  ): Promise<SymmetricKey> {
    let userKey: SymmetricKey | undefined;
    try {
      userKey = await this.deps.session.loadUserKey();
    } catch {
      this.assertOperation(operation);
      throw contextUnavailable();
    }
    this.assertOperation(operation);
    assertUserKey(userKey);

    let active: ActiveAuth | undefined;
    try {
      active = await this.deps.session.getActiveAuth();
    } catch {
      this.assertOperation(operation);
      throw contextUnavailable();
    }
    this.assertOperation(operation);
    if (
      !active
      || active.email !== security.accountEmail
      || active.sessionBindingId !== security.sessionBindingId
      || active.accessToken !== security.accessToken
    ) {
      throw contextUnavailable();
    }
    return userKey;
  }

  private async fetchPendingRequest(
    operation: ApprovalOperation,
    accessToken: string,
    requestId: string,
  ): Promise<unknown> {
    try {
      const raw = await operation.api.getAuthRequest(accessToken, requestId);
      this.assertOperation(operation);
      return raw;
    } catch {
      this.assertOperation(operation);
      throw new AppError('error', 'The device login request could not be loaded.');
    }
  }

  private async validatePending(
    raw: unknown,
    security: ApprovalSecurityContext,
    operation: ApprovalOperation,
  ): Promise<ValidatedPendingRequest> {
    const now = this.readNow();
    const view = await inspectPendingDeviceLoginRequest(raw, security, now);
    this.assertOperation(operation);
    const parsed = parseAuthRequestResponse(raw, now);
    const publicKeyDigest = await sha256Base64Url(parsed.publicKey);
    this.assertOperation(operation);
    const snapshot: DecisionSnapshot = Object.freeze({
      requestId: parsed.id,
      publicKey: parsed.publicKey,
      publicKeyDigest,
      requestDeviceIdentifier: parsed.requestDeviceIdentifier,
      creationDate: parsed.creationDate,
      requestDeviceTypeValue: parsed.requestDeviceTypeValue,
    });
    return Object.freeze({ raw, parsed, view, snapshot });
  }

  private async issueBinding(
    snapshot: DecisionSnapshot,
    security: ApprovalSecurityContext,
    operation: ApprovalOperation,
  ): Promise<DeviceLoginDecisionBinding> {
    const unsigned = Object.freeze({
      version: BINDING_VERSION,
      requestId: snapshot.requestId,
      publicKeyDigest: snapshot.publicKeyDigest,
      requestDeviceIdentifier: snapshot.requestDeviceIdentifier,
      creationDate: snapshot.creationDate,
      requestDeviceTypeValue: snapshot.requestDeviceTypeValue,
      nonce: bytesToBase64Url(randomBytes(BINDING_NONCE_BYTES)),
    });
    const proof = await this.signBinding(unsigned, security, operation);
    this.assertOperation(operation);
    return Object.freeze({ ...unsigned, proof });
  }

  private async assertAuthenticBinding(
    binding: DeviceLoginDecisionBinding,
    security: ApprovalSecurityContext,
    operation: ApprovalOperation,
  ): Promise<void> {
    const expected = await this.signBinding(binding, security, operation);
    this.assertOperation(operation);
    if (!constantTimeBase64UrlEqual(binding.proof, expected, BINDING_KEY_BYTES)) {
      throw staleDecisionBinding();
    }
  }

  private async signBinding(
    binding: Omit<DeviceLoginDecisionBinding, 'proof'>,
    security: ApprovalSecurityContext,
    operation: ApprovalOperation,
  ): Promise<string> {
    const payload = utf8ToBytes(JSON.stringify([
      binding.version,
      binding.requestId,
      binding.publicKeyDigest,
      binding.requestDeviceIdentifier,
      binding.creationDate,
      binding.requestDeviceTypeValue,
      binding.nonce,
      operation.accountLease.serverUrl,
      operation.accountLease.accountIdentity,
      operation.sessionLease.generation,
      security.sessionBindingId,
      security.approvalDeviceIdentifier,
    ]));
    try {
      const proof = await hmacSha256(this.bindingKey, payload);
      try {
        return bytesToBase64Url(proof);
      } finally {
        proof.fill(0);
      }
    } finally {
      payload.fill(0);
    }
  }

  private consumeBinding(binding: DeviceLoginDecisionBinding): number {
    const now = this.readNow();
    for (const [proof, expiresAt] of this.consumedBindings) {
      if (expiresAt <= now) this.consumedBindings.delete(proof);
    }
    if (this.consumedBindings.has(binding.proof)) throw staleDecisionBinding();
    if (this.consumedBindings.size >= MAX_CONSUMED_BINDINGS) {
      throw new AppError('denied', 'Too many device login decisions are pending.');
    }
    const creationTime = Date.parse(binding.creationDate);
    const expiresAt = creationTime + DEVICE_LOGIN_REQUEST_TTL_MS;
    if (!Number.isFinite(creationTime) || !Number.isSafeInteger(expiresAt) || expiresAt <= now) {
      throw staleDecisionBinding();
    }
    this.consumedBindings.set(binding.proof, expiresAt);
    return expiresAt;
  }

  private claimRequest(
    binding: DeviceLoginDecisionBinding,
    operation: ApprovalOperation,
    expiresAt: number,
  ): string {
    const now = this.readNow();
    for (const [claim, deadline] of this.writtenRequestClaims) {
      if (deadline <= now) this.writtenRequestClaims.delete(claim);
    }
    const claim = JSON.stringify([
      operation.accountLease.serverUrl,
      operation.accountLease.accountIdentity,
      binding.requestId,
    ]);
    if (this.activeRequestClaims.has(claim) || this.writtenRequestClaims.has(claim)) {
      throw staleDecisionBinding();
    }
    if (this.writtenRequestClaims.size >= MAX_CONSUMED_BINDINGS) {
      throw new AppError('denied', 'Too many device login decisions are pending.');
    }
    this.activeRequestClaims.add(claim);
    if (expiresAt <= now) {
      this.activeRequestClaims.delete(claim);
      throw staleDecisionBinding();
    }
    return claim;
  }

  private readNow(): number {
    const now = this.now();
    if (!Number.isSafeInteger(now) || now < 0) throw contextUnavailable();
    return now;
  }
}

export function createDeviceLoginApprovalService(
  deps: DeviceLoginApprovalServiceDeps,
): DeviceLoginApprovalService {
  return new DeviceLoginApprovalService(deps);
}

function parseDecisionBinding(input: unknown): DeviceLoginDecisionBinding {
  const record = requireDataRecord(input, BINDING_FIELDS);
  if (record.version !== BINDING_VERSION) throw staleDecisionBinding();
  const requestId = requireRequestId(record.requestId);
  const publicKeyDigest = requireCanonicalBase64Url(
    record.publicKeyDigest,
    SHA256_BASE64URL_LENGTH,
    BINDING_KEY_BYTES,
  );
  const requestDeviceIdentifier = requireBoundedText(
    record.requestDeviceIdentifier,
    MAX_DEVICE_IDENTIFIER_LENGTH,
  );
  const creationDate = requireBoundedText(record.creationDate, 64);
  if (
    !Number.isInteger(record.requestDeviceTypeValue)
    || (record.requestDeviceTypeValue as number) < 0
    || (record.requestDeviceTypeValue as number) > 255
  ) {
    throw staleDecisionBinding();
  }
  const nonce = requireCanonicalBase64Url(
    record.nonce,
    NONCE_BASE64URL_LENGTH,
    BINDING_NONCE_BYTES,
  );
  const proof = requireCanonicalBase64Url(
    record.proof,
    SHA256_BASE64URL_LENGTH,
    BINDING_KEY_BYTES,
  );
  return Object.freeze({
    version: BINDING_VERSION,
    requestId,
    publicKeyDigest,
    requestDeviceIdentifier,
    creationDate,
    requestDeviceTypeValue: record.requestDeviceTypeValue as number,
    nonce,
    proof,
  });
}

function requireDataRecord(
  input: unknown,
  expectedFields: ReadonlySet<string>,
): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw staleDecisionBinding();
  }
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) throw staleDecisionBinding();
  const keys = Reflect.ownKeys(input);
  if (
    keys.length !== expectedFields.size
    || keys.some((key) => typeof key !== 'string' || !expectedFields.has(key))
  ) {
    throw staleDecisionBinding();
  }
  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) throw staleDecisionBinding();
    output[key] = descriptor.value;
  }
  return output;
}

function requireBoundActiveAuth(auth: ActiveAuth | undefined, lease: AccountLease): string {
  const normalizedEmail = auth?.email.trim().toLowerCase();
  if (
    !auth
    || !auth.sessionBindingId
    || auth.email !== normalizedEmail
    || auth.email !== lease.accountIdentity
  ) {
    throw contextUnavailable();
  }
  return auth.sessionBindingId;
}

function assertUserKey(userKey: SymmetricKey | undefined): asserts userKey is SymmetricKey {
  if (
    !userKey
    || !(userKey.encKey instanceof Uint8Array)
    || userKey.encKey.byteLength !== 32
    || !(userKey.macKey instanceof Uint8Array)
    || userKey.macKey.byteLength !== 32
  ) {
    throw new AppError('locked', 'The unlocked vault key is unavailable.');
  }
}

function assertDeviceIdentifier(value: string): void {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_DEVICE_IDENTIFIER_LENGTH
    || value !== value.trim()
    || containsControl(value)
  ) {
    throw contextUnavailable();
  }
}

function requireRequestId(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 36 || !UUID_PATTERN.test(value)) {
    throw invalidPendingRequest();
  }
  return value;
}

function requireCanonicalBase64Url(
  value: unknown,
  expectedLength: number,
  expectedBytes: number,
): string {
  if (
    typeof value !== 'string'
    || value.length !== expectedLength
    || !BASE64URL_PATTERN.test(value)
  ) {
    throw staleDecisionBinding();
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlToBytes(value);
  } catch {
    throw staleDecisionBinding();
  }
  try {
    if (decoded.byteLength !== expectedBytes || bytesToBase64Url(decoded) !== value) {
      throw staleDecisionBinding();
    }
  } finally {
    decoded.fill(0);
  }
  return value;
}

function requireBoundedText(value: unknown, maximumLength: number): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > maximumLength
    || containsControl(value)
  ) {
    throw staleDecisionBinding();
  }
  return value;
}

function assertBindingMatchesSnapshot(
  binding: DeviceLoginDecisionBinding,
  snapshot: DecisionSnapshot,
): void {
  if (
    binding.requestId !== snapshot.requestId
    || binding.requestDeviceIdentifier !== snapshot.requestDeviceIdentifier
    || binding.creationDate !== snapshot.creationDate
    || binding.requestDeviceTypeValue !== snapshot.requestDeviceTypeValue
    || !constantTimeBase64UrlEqual(
      binding.publicKeyDigest,
      snapshot.publicKeyDigest,
      BINDING_KEY_BYTES,
    )
  ) {
    throw staleDecisionBinding();
  }
}

async function sha256Base64Url(publicKey: string): Promise<string> {
  const bytes = base64ToBytes(publicKey);
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
    try {
      return bytesToBase64Url(digest);
    } finally {
      digest.fill(0);
    }
  } finally {
    bytes.fill(0);
  }
}

function constantTimeBase64UrlEqual(
  left: string,
  right: string,
  expectedBytes: number,
): boolean {
  let leftBytes: Uint8Array | undefined;
  let rightBytes: Uint8Array | undefined;
  try {
    leftBytes = base64UrlToBytes(left);
    rightBytes = base64UrlToBytes(right);
    return leftBytes.byteLength === expectedBytes
      && rightBytes.byteLength === expectedBytes
      && constantTimeEqual(leftBytes, rightBytes);
  } catch {
    return false;
  } finally {
    leftBytes?.fill(0);
    rightBytes?.fill(0);
  }
}

function validateDecisionResponse(
  rawResponse: unknown,
  expected: DecisionSnapshot,
  approved: boolean,
  sentKey: string | undefined,
  now: number,
): DeviceLoginDecisionReceipt {
  const parsed = parseAuthRequestResponse(
    approved ? rawResponse : normalizeDeniedEmptyKey(rawResponse),
    now,
  );
  if (
    !parsed.answered
    || parsed.responseDate === undefined
    || parsed.responseTime === undefined
    || parsed.requestApproved !== approved
    || parsed.id !== expected.requestId
    || parsed.publicKey !== expected.publicKey
    || parsed.requestDeviceIdentifier !== expected.requestDeviceIdentifier
    || parsed.creationDate !== expected.creationDate
    || parsed.requestDeviceTypeValue !== expected.requestDeviceTypeValue
    || parsed.masterPasswordHash !== undefined
  ) {
    throw new Error('invalid decision response');
  }
  assertCalendarDate(parsed.responseDate);
  if (
    parsed.responseTime < parsed.creationTime
    || parsed.responseTime >= parsed.creationTime + DEVICE_LOGIN_REQUEST_TTL_MS
    || parsed.responseTime > now + MAX_CLOCK_SKEW_MS
  ) {
    throw new Error('invalid decision response');
  }
  if (approved) {
    if (
      sentKey === undefined
      || parsed.key === undefined
      || !constantTimeTextEqual(parsed.key, sentKey)
    ) {
      throw new Error('invalid decision response');
    }
  } else if (parsed.key !== undefined) {
    throw new Error('invalid decision response');
  }
  return Object.freeze({
    requestId: parsed.id,
    requestApproved: approved,
    responseDate: parsed.responseDate,
  });
}

function normalizeDeniedEmptyKey(input: unknown): unknown {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return input;
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return input;
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== 'string')) return input;
  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) return input;
    output[key] = (key === 'key' || key === 'Key') && descriptor.value === ''
      ? null
      : descriptor.value;
  }
  return output;
}

function constantTimeTextEqual(left: string, right: string): boolean {
  const leftBytes = utf8ToBytes(left);
  const rightBytes = utf8ToBytes(right);
  try {
    return constantTimeEqual(leftBytes, rightBytes);
  } finally {
    leftBytes.fill(0);
    rightBytes.fill(0);
  }
}

function assertCalendarDate(value: string): void {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/.exec(value);
  if (!match) throw new Error('invalid decision response');
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const daysInMonth = month >= 1 && month <= 12
    ? new Date(Date.UTC(year, month, 0)).getUTCDate()
    : 0;
  if (day < 1 || day > daysInMonth) throw new Error('invalid decision response');
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function containsControl(value: string): boolean {
  return /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(value);
}

function contextUnavailable(): AppError {
  return new AppError('session_expired', 'The approving account session is no longer available.');
}

function invalidPendingRequest(): AppError {
  return new AppError('denied', 'The device login request is invalid or no longer pending.');
}

function staleDecisionBinding(): AppError {
  return new AppError('denied', 'The device login confirmation is invalid or stale.');
}

function decisionOutcomeUnknown(): AppError {
  return new AppError(
    'outcome_unknown',
    'The device login decision may have been applied. Refresh requests before taking another action.',
  );
}
