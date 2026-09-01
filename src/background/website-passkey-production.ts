import { AppError, type AppErrorCode } from '../core/errors.js';
import type { PolicyLease } from '../core/policy/effective-enterprise-policy.js';
import type { AccountLease } from '../core/session/account-gate.js';
import type { ActiveAuth, SessionLease } from '../core/session/session-manager.js';
import {
  normalizePasskeyResidentSelection,
  type PasskeyCreateRequest,
} from '../core/vault/fido2-create.js';
import type { PasskeyAssertion } from '../core/vault/fido2.js';
import type { PasskeyCandidate, PasskeyTarget } from '../core/vault/models.js';
import { isRegistrableRpId } from '../core/vault/domain.js';
import type {
  Fido2Registration,
  PasskeyCreateOptions,
} from '../core/vault/vault-service.js';
import type {
  CanonicalWebsitePasskeyCreateRequest,
  CanonicalWebsitePasskeyGetRequest,
  PasskeyAssertionResultSnapshot,
  PasskeyRegistrationResultSnapshot,
  WebsitePasskeyDisplayChoice,
  WebsitePasskeySelection,
} from '../messaging/website-passkey-port.js';
import type {
  WebsitePasskeyCreateExecutionResult,
  WebsitePasskeyAvailabilityAdapter,
  WebsitePasskeyAvailabilitySnapshot,
  WebsitePasskeyDocumentContext,
  WebsitePasskeySecurityAdapter,
  WebsitePasskeySecurityAssertOptions,
  WebsitePasskeySecurityBinding,
  WebsitePasskeySecuritySnapshot,
  WebsitePasskeyVaultAdapter,
} from './website-passkey-coordinator.js';
import type { WebsitePasskeyDocumentLease } from './website-passkey-document-gate.js';
import type { ServerCapabilityLease } from './server-capability-manager.js';
import type { WebsitePasskeyPermissionLease } from './website-passkey-permission-gate.js';
import type { WebsitePasskeyPolicyLease } from './website-passkey-policy.js';

const SECURITY_ERROR_MESSAGE = 'Website passkey authorization is unavailable.';
const INTERNAL_TRANSPORTS = Object.freeze(['internal'] as const);

interface LeaseGate<Lease extends object> {
  capture(): Lease;
  assert(lease: Lease): unknown;
}

interface WebsitePasskeyPolicyBoundary extends LeaseGate<WebsitePasskeyPolicyLease> {
  assertAllowed(lease: WebsitePasskeyPolicyLease, browserUrl: string): unknown;
}

interface WebsitePasskeyCapabilitySnapshot {
  readonly availability: 'available' | 'unavailable';
  readonly identity: {
    readonly serverUrl: string;
    readonly accountIdentity?: string;
  };
}

interface WebsitePasskeyCapabilityBoundary {
  resolve(): PromiseLike<WebsitePasskeyCapabilitySnapshot>;
  capture(): ServerCapabilityLease;
  assert(lease: ServerCapabilityLease): WebsitePasskeyCapabilitySnapshot;
}

interface WebsitePasskeySessionBoundary {
  getActiveAuth(): PromiseLike<Pick<ActiveAuth, 'email' | 'sessionBindingId'> | undefined>;
}

interface WebsitePasskeyPermissionBoundary {
  capture(browserUrl: string): PromiseLike<WebsitePasskeyPermissionLease>;
  assert(lease: WebsitePasskeyPermissionLease): unknown;
}

interface WebsitePasskeyDocumentBoundary {
  capture(
    context: WebsitePasskeyDocumentContext,
    operation?: CanonicalWebsitePasskeyGetRequest['kind'] | CanonicalWebsitePasskeyCreateRequest['kind'],
  ): PromiseLike<WebsitePasskeyDocumentLease>;
  assert(lease: WebsitePasskeyDocumentLease, context: WebsitePasskeyDocumentContext): void;
  assertCurrent(
    lease: WebsitePasskeyDocumentLease,
    context: WebsitePasskeyDocumentContext,
  ): PromiseLike<void>;
}

export interface WebsitePasskeyProductionSecurityDeps {
  readonly sessionGate: LeaseGate<SessionLease>;
  readonly accountGate: LeaseGate<AccountLease>;
  readonly enterprisePolicyGate: LeaseGate<PolicyLease>;
  readonly serverCapabilities: WebsitePasskeyCapabilityBoundary;
  readonly websitePolicyGate: WebsitePasskeyPolicyBoundary;
  readonly permissionGate: WebsitePasskeyPermissionBoundary;
  readonly documentGate: WebsitePasskeyDocumentBoundary;
  readonly session: WebsitePasskeySessionBoundary;
}

export interface WebsitePasskeyProductionAvailabilityDeps {
  readonly accountGate: LeaseGate<AccountLease>;
  readonly websitePolicyGate: WebsitePasskeyPolicyBoundary;
  readonly permissionGate: WebsitePasskeyPermissionBoundary;
  readonly documentGate: WebsitePasskeyDocumentBoundary;
  readonly session: { getState(): PromiseLike<'loggedOut' | 'locked' | 'restricted' | 'unlocked'> };
}

export interface WebsitePasskeyProductionAvailabilityProof {
  readonly accountLease: AccountLease;
  readonly websitePolicyLease: WebsitePasskeyPolicyLease;
  readonly permissionLease: WebsitePasskeyPermissionLease;
  readonly documentLease: WebsitePasskeyDocumentLease;
  readonly document: WebsitePasskeyDocumentContext;
  readonly sessionState: 'locked' | 'unlocked';
}

/**
 * Authorize interception and locked staging without touching an unlocked session or vault data.
 * Enterprise raw state and server capabilities do not currently decide website-passkey enablement;
 * the full security adapter still requires both before candidate discovery or ceremony promotion.
 */
export function createWebsitePasskeyAvailabilityAdapter(
  deps: WebsitePasskeyProductionAvailabilityDeps,
): WebsitePasskeyAvailabilityAdapter<WebsitePasskeyProductionAvailabilityProof> {
  const issuedProofs = new WeakSet<object>();

  const assertPublicLeases = (proof: WebsitePasskeyProductionAvailabilityProof): void => {
    if (!issuedProofs.has(proof)) throw securityError('denied');
    deps.accountGate.assert(proof.accountLease);
    deps.websitePolicyGate.assertAllowed(proof.websitePolicyLease, proof.document.url);
    deps.permissionGate.assert(proof.permissionLease);
    deps.documentGate.assert(proof.documentLease, proof.document);
  };

  const capture = async (
    context: WebsitePasskeyDocumentContext,
    operation: CanonicalWebsitePasskeyGetRequest['kind'] | CanonicalWebsitePasskeyCreateRequest['kind'],
  ): Promise<WebsitePasskeyAvailabilitySnapshot<WebsitePasskeyProductionAvailabilityProof>> => {
    try {
      const document = freezeAndValidateDocument(context);
      const accountLease = deps.accountGate.capture();
      const websitePolicyLease = deps.websitePolicyGate.capture();
      deps.accountGate.assert(accountLease);
      deps.websitePolicyGate.assertAllowed(websitePolicyLease, document.url);

      const documentLease = await deps.documentGate.capture(document, operation);
      deps.accountGate.assert(accountLease);
      deps.websitePolicyGate.assertAllowed(websitePolicyLease, document.url);
      deps.documentGate.assert(documentLease, document);

      const permissionLease = await deps.permissionGate.capture(document.url);
      deps.accountGate.assert(accountLease);
      deps.websitePolicyGate.assertAllowed(websitePolicyLease, document.url);
      deps.permissionGate.assert(permissionLease);
      deps.documentGate.assert(documentLease, document);

      const sessionState = await deps.session.getState();
      if (sessionState !== 'locked' && sessionState !== 'unlocked') throw securityError('locked');
      const proof: WebsitePasskeyProductionAvailabilityProof = Object.freeze({
        accountLease,
        websitePolicyLease,
        permissionLease,
        documentLease,
        document,
        sessionState,
      });
      issuedProofs.add(proof);
      assertPublicLeases(proof);
      return Object.freeze({
        proof,
        sessionState,
        accountIdentity: accountLease.accountIdentity,
        serverUrl: accountLease.serverUrl,
        policyGeneration: websitePolicyLease.generation,
      });
    } catch (error) {
      throw fixedSecurityError(error);
    }
  };

  return Object.freeze({
    capture,
    async assertCurrent(
      snapshot: WebsitePasskeyAvailabilitySnapshot<WebsitePasskeyProductionAvailabilityProof>,
    ): Promise<void> {
      try {
        const proof = snapshot?.proof;
        if (!proof || !issuedProofs.has(proof)
            || snapshot.sessionState !== proof.sessionState
            || snapshot.accountIdentity !== proof.accountLease.accountIdentity
            || snapshot.serverUrl !== proof.accountLease.serverUrl
            || snapshot.policyGeneration !== proof.websitePolicyLease.generation) {
          throw securityError('denied');
        }
        assertPublicLeases(proof);
        await deps.documentGate.assertCurrent(proof.documentLease, proof.document);
        assertPublicLeases(proof);
        if (await deps.session.getState() !== proof.sessionState) throw securityError('locked');
        assertPublicLeases(proof);
      } catch (error) {
        throw fixedSecurityError(error);
      }
    },
  });
}

export interface WebsitePasskeyProductionSecurityProof {
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly enterprisePolicyLease: PolicyLease;
  readonly serverCapabilityLease: ServerCapabilityLease;
  readonly websitePolicyLease: WebsitePasskeyPolicyLease;
  readonly permissionLease: WebsitePasskeyPermissionLease;
  readonly documentLease: WebsitePasskeyDocumentLease;
  readonly document: WebsitePasskeyDocumentContext;
  readonly sessionBindingId: string;
  readonly assertWriteCurrent: () => void;
}

/**
 * Compose every revocable production authorization needed by a website ceremony. The active auth
 * tokens are deliberately never retained: only their non-secret session binding is copied into the
 * proof after all leases have been revalidated.
 */
export function createWebsitePasskeySecurityAdapter(
  deps: WebsitePasskeyProductionSecurityDeps,
): WebsitePasskeySecurityAdapter<WebsitePasskeyProductionSecurityProof> {
  const issuedProofs = new WeakSet<object>();

  const assertStableLeases = (
    proof: WebsitePasskeyProductionSecurityProof,
    enterprisePolicyLease?: PolicyLease,
  ): WebsitePasskeyCapabilitySnapshot => {
    deps.sessionGate.assert(proof.sessionLease);
    deps.accountGate.assert(proof.accountLease);
    if (enterprisePolicyLease) deps.enterprisePolicyGate.assert(enterprisePolicyLease);
    deps.websitePolicyGate.assertAllowed(proof.websitePolicyLease, proof.document.url);
    deps.permissionGate.assert(proof.permissionLease);
    deps.documentGate.assert(proof.documentLease, proof.document);
    const capability = deps.serverCapabilities.assert(proof.serverCapabilityLease);
    if (enterprisePolicyLease) {
      assertEnterpriseScopeMatchesAccount(enterprisePolicyLease, proof.accountLease);
    }
    assertCapabilityMatchesAccount(capability, proof.accountLease);
    return capability;
  };

  const capture = async (
    context: WebsitePasskeyDocumentContext,
    operation?: CanonicalWebsitePasskeyGetRequest['kind'] | CanonicalWebsitePasskeyCreateRequest['kind'],
  ): Promise<WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>> => {
    try {
      const document = freezeAndValidateDocument(context);
      // Capture every synchronous fence before capability discovery or storage can yield.
      const sessionLease = deps.sessionGate.capture();
      const accountLease = deps.accountGate.capture();
      const enterprisePolicyLease = deps.enterprisePolicyGate.capture();
      const websitePolicyLease = deps.websitePolicyGate.capture();
      deps.sessionGate.assert(sessionLease);
      deps.accountGate.assert(accountLease);
      deps.enterprisePolicyGate.assert(enterprisePolicyLease);
      deps.websitePolicyGate.assertAllowed(websitePolicyLease, document.url);
      assertEnterpriseScopeMatchesAccount(enterprisePolicyLease, accountLease);

      const documentLease = operation === undefined
        ? await deps.documentGate.capture(document)
        : await deps.documentGate.capture(document, operation);
      deps.sessionGate.assert(sessionLease);
      deps.accountGate.assert(accountLease);
      deps.enterprisePolicyGate.assert(enterprisePolicyLease);
      deps.websitePolicyGate.assertAllowed(websitePolicyLease, document.url);
      deps.documentGate.assert(documentLease, document);
      assertEnterpriseScopeMatchesAccount(enterprisePolicyLease, accountLease);

      const permissionLease = await deps.permissionGate.capture(document.url);
      deps.sessionGate.assert(sessionLease);
      deps.accountGate.assert(accountLease);
      deps.enterprisePolicyGate.assert(enterprisePolicyLease);
      deps.websitePolicyGate.assertAllowed(websitePolicyLease, document.url);
      deps.permissionGate.assert(permissionLease);
      deps.documentGate.assert(documentLease, document);
      assertEnterpriseScopeMatchesAccount(enterprisePolicyLease, accountLease);

      await deps.serverCapabilities.resolve();
      const serverCapabilityLease = deps.serverCapabilities.capture();
      deps.sessionGate.assert(sessionLease);
      deps.accountGate.assert(accountLease);
      deps.enterprisePolicyGate.assert(enterprisePolicyLease);
      deps.websitePolicyGate.assertAllowed(websitePolicyLease, document.url);
      deps.permissionGate.assert(permissionLease);
      deps.documentGate.assert(documentLease, document);
      const resolvedCapability = deps.serverCapabilities.assert(serverCapabilityLease);
      assertEnterpriseScopeMatchesAccount(enterprisePolicyLease, accountLease);
      assertCapabilityMatchesAccount(resolvedCapability, accountLease);

      const activeAuth = await deps.session.getActiveAuth();

      deps.sessionGate.assert(sessionLease);
      deps.accountGate.assert(accountLease);
      deps.enterprisePolicyGate.assert(enterprisePolicyLease);
      deps.websitePolicyGate.assertAllowed(websitePolicyLease, document.url);
      deps.permissionGate.assert(permissionLease);
      deps.documentGate.assert(documentLease, document);
      const currentCapability = deps.serverCapabilities.assert(serverCapabilityLease);
      assertEnterpriseScopeMatchesAccount(enterprisePolicyLease, accountLease);
      assertCapabilityMatchesAccount(currentCapability, accountLease);
      const sessionBindingId = requireMatchingActiveAuth(activeAuth, accountLease);

      const proof: WebsitePasskeyProductionSecurityProof = Object.freeze({
        sessionLease,
        accountLease,
        enterprisePolicyLease,
        serverCapabilityLease,
        websitePolicyLease,
        permissionLease,
        documentLease,
        document,
        sessionBindingId,
        assertWriteCurrent: (): void => {
          try {
            if (!issuedProofs.has(proof)) throw securityError('denied');
            assertStableLeases(proof, proof.enterprisePolicyLease);
          } catch (error) {
            throw fixedSecurityError(error);
          }
        },
      });
      issuedProofs.add(proof);
      return Object.freeze({
        proof,
        sessionBindingId,
        accountIdentity: accountLease.accountIdentity,
        serverUrl: accountLease.serverUrl,
        rawGeneration: enterprisePolicyLease.rawGeneration,
        policyGeneration: websitePolicyLease.generation,
      });
    } catch (error) {
      throw fixedSecurityError(error);
    }
  };

  const assertCurrent = async (
    snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
    options: WebsitePasskeySecurityAssertOptions = {},
  ): Promise<void> => {
    try {
      const proof = requireIssuedProof(snapshot, issuedProofs);
      assertSnapshotMatchesProof(snapshot, proof);
      // A committed create can rotate the raw cache and temporarily leave policy unpublished.
      // That path still retains every non-vault fence but deliberately skips the old raw lease.
      const enterprisePolicyLease = options.allowVaultGenerationChange === true
        ? undefined
        : proof.enterprisePolicyLease;
      assertStableLeases(proof, enterprisePolicyLease);
      await deps.documentGate.assertCurrent(proof.documentLease, proof.document);
      assertStableLeases(proof, enterprisePolicyLease);
      const activeAuth = await deps.session.getActiveAuth();
      assertStableLeases(proof, enterprisePolicyLease);
      if (requireMatchingActiveAuth(activeAuth, proof.accountLease) !== proof.sessionBindingId) {
        throw securityError('session_expired');
      }
    } catch (error) {
      throw fixedSecurityError(error);
    }
  };

  const assertDeliveryCurrent = (
    snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
    options: WebsitePasskeySecurityAssertOptions = {},
  ): void => {
    try {
      const proof = requireIssuedProof(snapshot, issuedProofs);
      assertSnapshotMatchesProof(snapshot, proof);
      const enterprisePolicyLease = options.allowVaultGenerationChange === true
        ? undefined
        : proof.enterprisePolicyLease;
      deps.accountGate.assert(proof.accountLease);
      if (enterprisePolicyLease) deps.enterprisePolicyGate.assert(enterprisePolicyLease);
      deps.websitePolicyGate.assertAllowed(proof.websitePolicyLease, proof.document.url);
      deps.permissionGate.assert(proof.permissionLease);
      deps.documentGate.assert(proof.documentLease, proof.document);
      const capability = deps.serverCapabilities.assert(proof.serverCapabilityLease);
      if (enterprisePolicyLease) {
        assertEnterpriseScopeMatchesAccount(enterprisePolicyLease, proof.accountLease);
      }
      assertCapabilityMatchesAccount(capability, proof.accountLease);
      // Keep the timeout-aware session preflight immediately adjacent to Port delivery.
      deps.sessionGate.assert(proof.sessionLease);
    } catch (error) {
      throw fixedSecurityError(error);
    }
  };

  return Object.freeze({
    capture,
    assertCurrent,
    assertDeliveryCurrent,
    async assertBindingCurrent(
      binding: WebsitePasskeySecurityBinding,
      document: WebsitePasskeyDocumentContext,
      options: WebsitePasskeySecurityAssertOptions = {},
    ): Promise<WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>> {
      let current: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>;
      try {
        current = await capture(document, options.operation);
        const allowVaultGenerationChange = options.allowVaultGenerationChange === true;
        if (!sameStableBinding(binding, current)
          || (!allowVaultGenerationChange && !sameVaultBinding(binding, current))) {
          throw securityError('denied');
        }
        await assertCurrent(current, options);
        return current;
      } catch (error) {
        throw fixedSecurityError(error);
      }
    },
  });
}

export interface WebsitePasskeyProductionVault {
  listPasskeyCandidates(request: {
    readonly rpId: string;
    readonly origin: string;
    readonly allowedCredentialIds?: readonly string[];
  }): PromiseLike<readonly PasskeyCandidate[]>;
  getPasskeyTargets(request: {
    readonly rpId: string;
    readonly origin: string;
  }): PromiseLike<readonly PasskeyTarget[]>;
  getPasskeyAssertion(request: {
    readonly rpId: string;
    readonly origin: string;
    readonly challenge: string;
    readonly allowedCredentialIds?: readonly string[];
    readonly crossOrigin?: boolean;
  }): PromiseLike<PasskeyAssertion | undefined>;
  createPasskey(
    request: PasskeyCreateRequest,
    options?: PasskeyCreateOptions,
  ): PromiseLike<Fido2Registration>;
}

/** Keep all website-facing result construction at one narrow, public-data-only boundary. */
export function createWebsitePasskeyVaultAdapter(
  vault: WebsitePasskeyProductionVault,
): WebsitePasskeyVaultAdapter<WebsitePasskeyProductionSecurityProof> {
  return Object.freeze({
    async prepareGet(
      request: CanonicalWebsitePasskeyGetRequest,
      origin: string,
      _snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
      signal: AbortSignal,
    ): Promise<readonly WebsitePasskeyDisplayChoice[]> {
      assertNotAborted(signal);
      assertRpIdForOrigin(request.rpId, origin);
      const candidates = await vault.listPasskeyCandidates({
        rpId: request.rpId,
        origin,
        allowedCredentialIds: credentialIds(request.allowCredentials),
      });
      assertNotAborted(signal);
      return Object.freeze(candidates
        .filter((candidate) => candidate.requiresReprompt !== true)
        .map((candidate) => freezeDisplayChoice(candidate.credentialId, candidate)));
    },

    async prepareCreate(
      request: CanonicalWebsitePasskeyCreateRequest,
      origin: string,
      _snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
      signal: AbortSignal,
    ): Promise<readonly WebsitePasskeyDisplayChoice[]> {
      assertNotAborted(signal);
      assertRpIdForOrigin(request.rp.id, origin);
      const targets = await vault.getPasskeyTargets({ rpId: request.rp.id, origin });
      assertNotAborted(signal);
      return Object.freeze(targets
        .filter((target) => target.requiresReprompt !== true)
        .map((target) => freezeDisplayChoice(target.id, target)));
    },

    async executeGet(
      request: CanonicalWebsitePasskeyGetRequest,
      origin: string,
      credentialId: string,
      snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
      signal: AbortSignal,
    ): Promise<PasskeyAssertionResultSnapshot | undefined> {
      assertNotAborted(signal);
      assertRpIdForOrigin(request.rpId, origin);
      const crossOrigin = trustedCrossOrigin(snapshot, 'get');
      const assertion = await vault.getPasskeyAssertion({
        rpId: request.rpId,
        origin,
        challenge: request.challenge,
        allowedCredentialIds: Object.freeze([credentialId]),
        ...(crossOrigin ? { crossOrigin: true } : {}),
      });
      assertNotAborted(signal);
      if (!assertion) return undefined;
      if (assertion.credentialId !== credentialId) {
        throw new AppError('denied', 'The selected passkey is no longer available.');
      }
      return freezeAssertionResult(assertion);
    },

    async executeCreate(
      request: CanonicalWebsitePasskeyCreateRequest,
      origin: string,
      selection: Extract<WebsitePasskeySelection, { kind: 'new' | 'target' }>,
      snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
      signal: AbortSignal,
    ): Promise<WebsitePasskeyCreateExecutionResult> {
      assertNotAborted(signal);
      assertRpIdForOrigin(request.rp.id, origin);
      const crossOrigin = trustedCrossOrigin(snapshot, 'create');
      try {
        const assertAuthorized = requireWriteGuard(snapshot);
        assertAuthorized();
        const registration = await vault.createPasskey({
          rpId: request.rp.id,
          rpName: request.rp.name,
          userHandle: request.user.id,
          userName: request.user.name,
          userDisplayName: request.user.displayName,
          challenge: request.challenge,
          origin,
          residentKey: request.authenticatorSelection.residentKey,
          requireResidentKey: request.authenticatorSelection.requireResidentKey,
          excludeCredentialIds: credentialIds(request.excludeCredentials),
          ...(request.authenticatorSelection.authenticatorAttachment === undefined
            ? {}
            : { authenticatorAttachment: request.authenticatorSelection.authenticatorAttachment }),
          ...(crossOrigin ? { crossOrigin: true } : {}),
          ...(selection.kind === 'target' ? { targetCipherId: selection.cipherId } : {}),
        }, { assertAuthorized });
        // A resolved core call is an authoritative commit fact. A late abort cannot make it unknown.
        const resident = normalizePasskeyResidentSelection(
          request.authenticatorSelection.residentKey,
          request.authenticatorSelection.requireResidentKey,
        );
        return Object.freeze({
          status: 'committed' as const,
          result: freezeRegistrationResult(
            registration,
            request.extensions.credProps ? resident.discoverable : undefined,
          ),
        });
      } catch (error) {
        if (!(error instanceof AppError)) throw error;
        return classifyCreateError(error);
      }
    },
  });
}

function freezeAndValidateDocument(context: WebsitePasskeyDocumentContext): WebsitePasskeyDocumentContext {
  if (!Number.isSafeInteger(context.tabId) || context.tabId < 0
    || !Number.isSafeInteger(context.frameId) || context.frameId < 0
    || typeof context.documentId !== 'string'
    || context.documentId.length === 0
    || typeof context.url !== 'string'
    || typeof context.origin !== 'string') {
    throw securityError('denied');
  }
  let parsed: URL;
  try {
    parsed = new URL(context.url);
  } catch {
    throw securityError('denied');
  }
  if (parsed.origin !== context.origin) throw securityError('denied');
  return Object.freeze({ ...context });
}

function requireIssuedProof(
  snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
  issuedProofs: WeakSet<object>,
): WebsitePasskeyProductionSecurityProof {
  if (typeof snapshot !== 'object' || snapshot === null
    || typeof snapshot.proof !== 'object' || snapshot.proof === null
    || !issuedProofs.has(snapshot.proof)) {
    throw securityError('denied');
  }
  return snapshot.proof;
}

function requireWriteGuard(
  snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
): () => void {
  const guard = snapshot?.proof?.assertWriteCurrent;
  if (typeof guard !== 'function') throw securityError('denied');
  return guard;
}

function trustedCrossOrigin(
  snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
  operation: 'get' | 'create',
): boolean {
  const lease = snapshot?.proof?.documentLease;
  // Legacy unit adapters predate the document proof. Production security snapshots always carry it.
  if (!lease) return false;
  if (lease.operation !== operation
    || typeof lease.crossOrigin !== 'boolean'
    || typeof lease.topOrigin !== 'string'
    || !lease.topOrigin) throw securityError('denied');
  return lease.crossOrigin;
}

function assertSnapshotMatchesProof(
  snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
  proof: WebsitePasskeyProductionSecurityProof,
): void {
  if (snapshot.sessionBindingId !== proof.sessionBindingId
    || snapshot.accountIdentity !== proof.accountLease.accountIdentity
    || snapshot.serverUrl !== proof.accountLease.serverUrl
    || snapshot.rawGeneration !== proof.enterprisePolicyLease.rawGeneration
    || snapshot.policyGeneration !== proof.websitePolicyLease.generation
    || Object.prototype.hasOwnProperty.call(snapshot, 'snapshotGeneration')) {
    throw securityError('denied');
  }
}

function assertEnterpriseScopeMatchesAccount(policy: PolicyLease, account: AccountLease): void {
  if (policy.serverGeneration !== account.serverGeneration
    || policy.accountGeneration !== account.accountGeneration
    || policy.serverUrl !== account.serverUrl
    || policy.accountIdentity !== account.accountIdentity) {
    throw securityError('denied');
  }
}

function assertCapabilityMatchesAccount(
  capability: WebsitePasskeyCapabilitySnapshot,
  account: AccountLease,
): void {
  if (capability.availability !== 'available'
    || capability.identity.serverUrl !== account.serverUrl
    || capability.identity.accountIdentity !== account.accountIdentity) {
    throw securityError('sync_required');
  }
}

function requireMatchingActiveAuth(
  activeAuth: Pick<ActiveAuth, 'email' | 'sessionBindingId'> | undefined,
  account: AccountLease,
): string {
  const sessionBindingId = activeAuth?.sessionBindingId;
  if (!activeAuth
    || activeAuth.email.trim().toLowerCase() !== account.accountIdentity
    || typeof sessionBindingId !== 'string'
    || sessionBindingId.length === 0) {
    throw securityError('session_expired');
  }
  return sessionBindingId;
}

function sameStableBinding(
  binding: WebsitePasskeySecurityBinding,
  current: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
): boolean {
  return binding.sessionBindingId === current.sessionBindingId
    && binding.accountIdentity === current.accountIdentity
    && binding.serverUrl === current.serverUrl
    && binding.policyGeneration === current.policyGeneration;
}

function sameVaultBinding(
  binding: WebsitePasskeySecurityBinding,
  current: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
): boolean {
  const bindingHasSnapshot = Object.prototype.hasOwnProperty.call(binding, 'snapshotGeneration');
  const currentHasSnapshot = Object.prototype.hasOwnProperty.call(current, 'snapshotGeneration');
  return binding.rawGeneration === current.rawGeneration
    && bindingHasSnapshot === currentHasSnapshot
    && (!bindingHasSnapshot || binding.snapshotGeneration === current.snapshotGeneration);
}

function fixedSecurityError(error: unknown): AppError {
  return error instanceof AppError
    ? securityError(error.code)
    : securityError('denied');
}

function securityError(code: AppErrorCode): AppError {
  return new AppError(code, SECURITY_ERROR_MESSAGE);
}

function assertNotAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
}

function assertRpIdForOrigin(rpId: string, origin: string): void {
  let url: URL;
  try { url = new URL(origin); } catch { throw securityError('denied'); }
  if (url.origin !== origin || !isRegistrableRpId(rpId, url.hostname)) {
    throw securityError('denied');
  }
}

function credentialIds(
  descriptors: readonly { readonly id: string }[],
): readonly string[] {
  return Object.freeze(descriptors.map(({ id }) => id));
}

function freezeDisplayChoice(
  id: string,
  item: { readonly name: string; readonly username?: string },
): WebsitePasskeyDisplayChoice {
  return Object.freeze({
    id,
    name: item.name,
    ...(item.username === undefined ? {} : { username: item.username }),
  });
}

function freezeAssertionResult(assertion: PasskeyAssertion): PasskeyAssertionResultSnapshot {
  return Object.freeze({
    kind: 'get',
    authenticatorAttachment: 'platform',
    transports: INTERNAL_TRANSPORTS,
    credentialId: assertion.credentialId,
    authenticatorData: assertion.authenticatorData,
    clientDataJSON: assertion.clientDataJSON,
    signature: assertion.signature,
    ...(assertion.userHandle === undefined ? {} : { userHandle: assertion.userHandle }),
  });
}

function freezeRegistrationResult(
  registration: Fido2Registration,
  resident: boolean | undefined,
): PasskeyRegistrationResultSnapshot {
  return Object.freeze({
    kind: 'create',
    authenticatorAttachment: 'platform',
    transports: INTERNAL_TRANSPORTS,
    credProps: resident === undefined ? null : Object.freeze({ rk: resident }),
    credentialId: registration.credentialId,
    attestationObject: registration.attestationObject,
    clientDataJSON: registration.clientDataJSON,
    authData: registration.authData,
    publicKeySpki: registration.publicKeySpki,
    publicKeyAlgorithm: -7,
  });
}

function classifyCreateError(error: AppError): WebsitePasskeyCreateExecutionResult {
  switch (error.code) {
    case 'outcome_unknown':
    case 'committed_unsynced':
      return Object.freeze({ status: 'outcome_unknown' as const });
    case 'conflict':
    case 'stale_form':
      return Object.freeze({ status: 'not_committed' as const, reason: 'invalid_state' as const });
    case 'no_match':
      return Object.freeze({ status: 'not_committed' as const, reason: 'not_supported' as const });
    case 'locked':
    case 'session_expired':
    case 'sync_required':
    case 'denied':
    case 'reprompt_required':
      return Object.freeze({ status: 'not_committed' as const, reason: 'not_allowed' as const });
    default:
      return Object.freeze({ status: 'not_committed' as const, reason: 'operation_failed' as const });
  }
}
