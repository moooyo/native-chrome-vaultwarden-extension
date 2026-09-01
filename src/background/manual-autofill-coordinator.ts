import { AppError } from '../core/errors.js';
import type { AccountLease, AccountLeaseGate } from '../core/session/account-gate.js';
import type { SessionLease, SessionLeaseGate } from '../core/session/session-manager.js';
import type { PolicyLease } from '../core/policy/effective-enterprise-policy.js';
import type {
  ManualAutofillCommitOutcome,
  ManualAutofillPreparationData,
} from '../messaging/protocol.js';
import type {
  ManualAutofillVaultAuthority,
  ManualAutofillVaultBinding,
  ManualAutofillVaultPreparation,
  VaultService,
} from '../core/vault/vault-service.js';
import type { AutofillAuthorizationPolicyLease } from './autofill-authorization-policy.js';
import type {
  ManualAutofillGrantBinding,
  ManualAutofillGrantRegistry,
  RedeemedManualAutofillGrant,
} from './manual-autofill-grant-registry.js';
import type {
  RepromptAutofillGrantBinding,
  RepromptAutofillGrantRegistry,
} from './reprompt-autofill-grant-registry.js';
import type {
  ResolvedManualAutofillTarget,
  TabAutofillCoordinator,
} from './tab-autofill.js';

type ManualGrantRegistry = ManualAutofillGrantRegistry<
  SessionLease,
  AccountLease,
  AutofillAuthorizationPolicyLease,
  PolicyLease,
  ManualAutofillVaultAuthority
>;

type RedeemedManualGrant = RedeemedManualAutofillGrant<
  SessionLease,
  AccountLease,
  AutofillAuthorizationPolicyLease,
  PolicyLease,
  ManualAutofillVaultAuthority
>;

export interface ManualAutofillCoordinatorDeps {
  readonly grants: ManualGrantRegistry;
  readonly repromptGrants: RepromptAutofillGrantRegistry<
    SessionLease,
    AccountLease,
    AutofillAuthorizationPolicyLease
  >;
  readonly tabAutofill: Pick<
    TabAutofillCoordinator,
    'resolveManualLoginTarget' | 'fillManual'
  >;
  readonly vault: Pick<
    VaultService,
    'prepareManualAutofill' | 'saveManualAutofillUri'
  >;
  readonly sessionGate: SessionLeaseGate;
  readonly accountGate: Pick<AccountLeaseGate, 'capture' | 'assert'>;
  readonly capturePolicy: () => AutofillAuthorizationPolicyLease;
  readonly assertPolicy: (lease: AutofillAuthorizationPolicyLease) => void;
  readonly authorizeSave: (
    url: string,
    lease: AutofillAuthorizationPolicyLease,
  ) => Promise<{ readonly assertCurrent: () => void }>;
  readonly verifyMasterPassword: (password: string) => Promise<boolean>;
}

export interface ManualAutofillCoordinator {
  prepare(popupDocumentId: string, input: unknown): Promise<ManualAutofillPreparationData>;
  cancel(popupDocumentId: string, input: unknown): boolean;
  commit(popupDocumentId: string, input: unknown): Promise<ManualAutofillCommitOutcome>;
  revokeAll(): void;
}

const PREPARE_KEYS = ['type', 'tabId', 'cipherId'] as const;
const CANCEL_KEYS = ['type', 'authorizationId'] as const;
const COMMIT_KEYS = ['type', 'authorizationId', 'action'] as const;
const COMMIT_PASSWORD_KEYS = [...COMMIT_KEYS, 'masterPassword'] as const;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_ID_LENGTH = 4_096;

export function createManualAutofillCoordinator(
  deps: ManualAutofillCoordinatorDeps,
): ManualAutofillCoordinator {
  const assertLeases = (
    sessionLease: SessionLease,
    accountLease: AccountLease,
    policyLease: AutofillAuthorizationPolicyLease,
  ): void => {
    deps.sessionGate.assert(sessionLease);
    deps.accountGate.assert(accountLease);
    deps.assertPolicy(policyLease);
  };

  async function prepare(
    popupDocumentIdInput: string,
    input: unknown,
  ): Promise<ManualAutofillPreparationData> {
    const popupDocumentId = opaqueId(popupDocumentIdInput, 'Popup document');
    const request = exactRecord(input, PREPARE_KEYS);
    if (dataValue(request, 'type') !== 'autofill.manual.prepare') invalidRequest();
    const tabId = nonNegativeInteger(dataValue(request, 'tabId'), 'tab');
    const cipherId = opaqueId(dataValue(request, 'cipherId'), 'cipher');
    const sessionLease = deps.sessionGate.capture();
    const accountLease = deps.accountGate.capture();
    const policyLease = deps.capturePolicy();
    assertLeases(sessionLease, accountLease, policyLease);

    const firstTarget = await deps.tabAutofill.resolveManualLoginTarget(tabId);
    assertLeases(sessionLease, accountLease, policyLease);
    if (!firstTarget) throw new AppError('denied', 'Manual autofill requires one current login form.');
    const vault = await deps.vault.prepareManualAutofill(
      cipherId,
      firstTarget.frameUrl,
      firstTarget.defaultStrategy,
      firstTarget.topUrl,
    );
    assertLeases(sessionLease, accountLease, policyLease);
    vault.authority.assertCurrent();
    const finalTarget = await deps.tabAutofill.resolveManualLoginTarget(tabId);
    assertLeases(sessionLease, accountLease, policyLease);
    vault.authority.assertCurrent();
    if (!finalTarget || !sameResolvedTarget(firstTarget, finalTarget)) {
      throw new AppError('conflict', 'The manual autofill target changed.');
    }

    let saveAuthorized = false;
    if (vault.canSave && vault.risk === 'no_match') {
      try {
        const authorization = await deps.authorizeSave(finalTarget.topUrl, policyLease);
        assertLeases(sessionLease, accountLease, policyLease);
        vault.authority.assertCurrent();
        authorization.assertCurrent();
        saveAuthorized = true;
      } catch {
        saveAuthorized = false;
      }
    }
    const allowedActions = saveAuthorized
      ? Object.freeze(['fill_only', 'fill_and_save'] as const)
      : Object.freeze(['fill_only'] as const);
    const receipt = deps.grants.issue({
      ...grantBinding(popupDocumentId, cipherId, finalTarget, vault),
      allowedActions,
      sessionLease,
      accountLease,
      autofillPolicyLease: policyLease,
      enterprisePolicyLease: policyLease.enterprise,
      vaultAuthority: vault.authority,
    });
    const site = new URL(finalTarget.topUrl).hostname;
    const recipientSite = new URL(finalTarget.frameUrl).hostname;
    return Object.freeze({
      warning: Object.freeze({
        risk: vault.risk,
        site,
        ...(recipientSite === site ? {} : { recipientSite }),
        canSave: allowedActions.length === 2,
        requiresReprompt: vault.requiresReprompt,
      }),
      authorization: Object.freeze({
        authorizationId: receipt.grantId,
        expiresAt: receipt.expiresAt,
      }),
    });
  }

  function cancel(popupDocumentIdInput: string, input: unknown): boolean {
    const unsafeId = ownDataValue(input, 'authorizationId');
    const cancelled = deps.grants.cancel(
      typeof unsafeId === 'string' ? unsafeId : '',
      { popupDocumentId: popupDocumentIdInput },
    );
    const popupDocumentId = opaqueId(popupDocumentIdInput, 'Popup document');
    const request = exactRecord(input, CANCEL_KEYS);
    if (dataValue(request, 'type') !== 'autofill.manual.cancel'
        || !UUID_V4.test(opaqueId(dataValue(request, 'authorizationId'), 'authorization'))) {
      invalidRequest();
    }
    if (!cancelled || popupDocumentId.length === 0) invalidAuthorization();
    return true;
  }

  async function commit(
    popupDocumentIdInput: string,
    input: unknown,
  ): Promise<ManualAutofillCommitOutcome> {
    // Extract only the capability and action before redemption. Every remaining field, including the
    // request shape and password, is validated after the one-time grant has already been consumed.
    const unsafeId = ownDataValue(input, 'authorizationId');
    const unsafeAction = ownDataValue(input, 'action');
    const grant = deps.grants.redeem(
      typeof unsafeId === 'string' ? unsafeId : '',
      { popupDocumentId: popupDocumentIdInput },
      unsafeAction as 'fill_only' | 'fill_and_save',
    );
    if (!grant) invalidAuthorization();

    const hasPassword = ownDataValue(input, 'masterPassword') !== undefined;
    const request = exactRecord(input, hasPassword ? COMMIT_PASSWORD_KEYS : COMMIT_KEYS);
    if (dataValue(request, 'type') !== 'autofill.manual.commit') invalidRequest();
    const authorizationId = opaqueId(dataValue(request, 'authorizationId'), 'authorization');
    if (!UUID_V4.test(authorizationId) || authorizationId !== unsafeId) invalidRequest();
    const action = dataValue(request, 'action');
    if (action !== 'fill_only' && action !== 'fill_and_save') invalidRequest();
    const masterPassword = ownDataValue(request, 'masterPassword');
    grant.assertCurrent();

    const target = await deps.tabAutofill.resolveManualLoginTarget(grant.binding.tabId);
    grant.assertCurrent();
    if (!target || !bindingMatchesTarget(grant.binding, target)) {
      throw new AppError('conflict', 'The manual autofill target changed.');
    }
    const vault = await deps.vault.prepareManualAutofill(
      grant.binding.cipherId,
      target.frameUrl,
      target.defaultStrategy,
      target.topUrl,
    );
    grant.assertCurrent();
    if (!sameVaultBinding(grant.binding, vault)
        || (action === 'fill_and_save' && (!vault.canSave || vault.risk !== 'no_match'))) {
      throw new AppError('conflict', 'The manual autofill login changed.');
    }
    const saveAuthorization = action === 'fill_and_save'
      ? await deps.authorizeSave(target.topUrl, grant.autofillPolicyLease)
      : undefined;
    grant.assertCurrent();
    saveAuthorization?.assertCurrent();

    const reprompt = await redeemRepromptProof(grant, masterPassword, target, vault);
    grant.assertCurrent();
    reprompt?.assertCurrent();
    const outcome = await deps.tabAutofill.fillManual(
      grant.binding.tabId,
      grant.binding.cipherId,
      target.target,
      vaultBinding(grant.binding),
      () => {
        grant.assertCurrent();
        reprompt?.assertCurrent();
      },
      reprompt ? { assertCurrent: reprompt.assertCurrent } : undefined,
    );
    if (outcome.status !== 'filled' || action === 'fill_only') return outcome;

    try {
      await deps.vault.saveManualAutofillUri(
        grant.binding.cipherId,
        target.frameUrl,
        target.topUrl,
        target.defaultStrategy,
        vaultBinding(grant.binding),
        () => {
          grant.assertCurrent();
          reprompt?.assertCurrent();
          saveAuthorization?.assertCurrent();
        },
      );
      return { status: 'filled_and_saved' };
    } catch (error) {
      if (error instanceof AppError && error.code === 'outcome_unknown') {
        return { status: 'filled_but_save_outcome_unknown' };
      }
      if (error instanceof AppError && error.code === 'conflict') {
        return { status: 'filled_but_save_conflict' };
      }
      if (error instanceof AppError && error.code === 'committed_unsynced') {
        return { status: 'filled_but_save_committed_unsynced' };
      }
      return { status: 'filled_but_save_failed' };
    }
  }

  async function redeemRepromptProof(
    grant: RedeemedManualGrant,
    passwordValue: unknown,
    target: ResolvedManualAutofillTarget,
    vault: ManualAutofillVaultPreparation,
  ): Promise<{ readonly assertCurrent: () => void } | undefined> {
    if (!vault.requiresReprompt) {
      if (passwordValue !== undefined) invalidRequest();
      return undefined;
    }
    if (typeof passwordValue !== 'string' || passwordValue.length < 1 || passwordValue.length > 4_096) {
      throw new AppError('reprompt_required', 'Master password verification is required.');
    }
    const verification = deps.verifyMasterPassword(passwordValue);
    if (!(await verification)) throw new AppError('reprompt_required', 'Master password verification failed.');
    grant.assertCurrent();
    const binding = repromptBinding(grant.binding, target);
    const receipt = deps.repromptGrants.issue({
      ...binding,
      sessionLease: grant.sessionLease,
      accountLease: grant.accountLease,
      policyLease: grant.autofillPolicyLease,
    });
    const proof = deps.repromptGrants.redeem(receipt.authorizationId, binding);
    if (!proof) invalidAuthorization();
    const assertCurrent = (): void => {
      grant.assertCurrent();
      if (!proof.isCurrent()) invalidAuthorization();
    };
    assertCurrent();
    return Object.freeze({ assertCurrent });
  }

  return Object.freeze({
    prepare,
    cancel,
    commit,
    revokeAll: () => deps.grants.revokeAll(),
  });
}

function grantBinding(
  popupDocumentId: string,
  cipherId: string,
  target: ResolvedManualAutofillTarget,
  vault: ManualAutofillVaultPreparation,
): ManualAutofillGrantBinding {
  return Object.freeze({
    popupDocumentId,
    cipherId,
    tabId: target.tabId,
    topUrl: target.topUrl,
    frameUrl: target.frameUrl,
    frameId: target.frameId,
    targetDocumentId: target.targetDocumentId,
    formId: target.target.formId,
    generation: target.target.generation,
    customPlanDigest: target.target.customPlanDigest,
    cipherRevision: vault.cipherRevision,
    uriDigest: vault.uriDigest,
    risk: vault.risk,
    requiresReprompt: vault.requiresReprompt,
  });
}

function repromptBinding(
  grant: ManualAutofillGrantBinding,
  target: ResolvedManualAutofillTarget,
): RepromptAutofillGrantBinding {
  return Object.freeze({
    popupDocumentId: grant.popupDocumentId,
    cipherId: grant.cipherId,
    tabId: grant.tabId,
    frameId: grant.frameId,
    targetDocumentId: grant.targetDocumentId,
    topUrl: grant.topUrl,
    frameUrl: grant.frameUrl,
    targetKey: target.targetKey,
  });
}

function vaultBinding(binding: ManualAutofillGrantBinding): ManualAutofillVaultBinding {
  return Object.freeze({
    cipherRevision: binding.cipherRevision,
    uriDigest: binding.uriDigest,
    risk: binding.risk,
    requiresReprompt: binding.requiresReprompt,
  });
}

function sameVaultBinding(
  binding: ManualAutofillGrantBinding,
  vault: ManualAutofillVaultPreparation,
): boolean {
  return binding.cipherRevision === vault.cipherRevision
    && binding.uriDigest === vault.uriDigest
    && binding.risk === vault.risk
    && binding.requiresReprompt === vault.requiresReprompt;
}

function sameResolvedTarget(
  first: ResolvedManualAutofillTarget,
  second: ResolvedManualAutofillTarget,
): boolean {
  return first.tabId === second.tabId
    && first.topUrl === second.topUrl
    && first.frameUrl === second.frameUrl
    && first.frameId === second.frameId
    && first.targetDocumentId === second.targetDocumentId
    && first.targetKey === second.targetKey
    && first.defaultStrategy === second.defaultStrategy;
}

function bindingMatchesTarget(
  binding: ManualAutofillGrantBinding,
  target: ResolvedManualAutofillTarget,
): boolean {
  return binding.tabId === target.tabId
    && binding.topUrl === canonicalHttpUrl(target.topUrl)
    && binding.frameUrl === canonicalHttpUrl(target.frameUrl)
    && binding.frameId === target.frameId
    && binding.targetDocumentId === target.targetDocumentId
    && binding.formId === target.target.formId
    && binding.generation === target.target.generation
    && binding.customPlanDigest === target.target.customPlanDigest;
}

function canonicalHttpUrl(value: string): string {
  try { return new URL(value).href; } catch { return ''; }
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalidRequest();
  const prototype = Object.getPrototypeOf(value) as object | null;
  const actual = Reflect.ownKeys(value);
  if ((prototype !== Object.prototype && prototype !== null)
      || actual.length !== keys.length
      || actual.some((key) => typeof key !== 'string' || !keys.includes(key))) invalidRequest();
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) invalidRequest();
  }
  return value as Record<string, unknown>;
}

function ownDataValue(value: unknown, key: string): unknown {
  try {
    if (typeof value !== 'object' || value === null) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && 'value' in descriptor ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  return ownDataValue(record, key);
}

function opaqueId(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID_LENGTH
      || value.trim() !== value) throw new AppError('denied', `${field} is invalid.`);
  return value;
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) {
    throw new AppError('denied', `${field} is invalid.`);
  }
  return value as number;
}

function invalidRequest(): never {
  throw new AppError('denied', 'Manual autofill request is invalid.');
}

function invalidAuthorization(): never {
  throw new AppError('denied', 'Manual autofill authorization is invalid or expired.');
}
