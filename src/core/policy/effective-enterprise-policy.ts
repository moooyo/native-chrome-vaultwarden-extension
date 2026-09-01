import type { OrganizationResponse, SyncResponse } from '../api/types.js';
import { AppError } from '../errors.js';
import type { AccountLease } from '../session/account-gate.js';
import {
  parseMasterPasswordPolicy,
  type MasterPasswordPolicy,
} from './master-password-policy.js';
import {
  combinePasswordGeneratorPolicyData,
  parsePasswordGeneratorPolicyData,
  type PasswordGeneratorPolicyData,
} from './password-generator-policy.js';
import {
  isUriMatchStrategySetting,
  UriMatchStrategy,
  type UriMatchStrategySetting,
} from '../vault/uri-match.js';

export const EnterprisePolicyType = Object.freeze({
  MasterPassword: 1,
  PasswordGenerator: 2,
  RequireSso: 4,
  OrganizationDataOwnership: 5,
  DisableSend: 6,
  SendOptions: 7,
  MaximumVaultTimeout: 9,
  DisablePersonalVaultExport: 10,
  ActivateAutofill: 11,
  RemoveUnlockWithPin: 14,
  RestrictedItemTypes: 15,
  UriMatchDefaults: 16,
  SendControls: 21,
} as const);

export type SupportedEnterprisePolicyType =
  (typeof EnterprisePolicyType)[keyof typeof EnterprisePolicyType];

export type EnterprisePolicySource = 'policiesNew' | 'policies' | 'none';
export type OrganizationContextSource = 'organizationsNew' | 'organizations' | 'none';

export type EnterprisePolicyCapability =
  | 'createPersonalVaultItem'
  | 'createOrEditSend'
  | 'exportPersonalVault'
  | 'unlockWithPin';

export type MaximumVaultTimeoutType =
  | null
  | 'never'
  | 'onAppRestart'
  | 'onSystemLock'
  | 'immediately'
  | 'custom';

export type MaximumVaultTimeoutAction = null | 'lock' | 'logOut';

export interface MaximumVaultTimeoutPolicyData {
  readonly type: MaximumVaultTimeoutType;
  readonly minutes: number;
  readonly action: MaximumVaultTimeoutAction;
}

export interface EffectiveMaximumVaultTimeoutPolicy {
  readonly organizationId: string | null;
  readonly malformed: boolean;
  readonly data: MaximumVaultTimeoutPolicyData;
}

export interface EffectivePasswordGeneratorPolicy {
  readonly malformed: boolean;
  readonly data: PasswordGeneratorPolicyData;
}

export type SendWhoCanAccess = 0 | 1 | 2;
export type SendItemType = 0 | 1;

export interface EffectiveSendControls {
  readonly disabled: boolean;
  readonly disableHideEmail: boolean;
  readonly whoCanAccess: SendWhoCanAccess;
  readonly allowedDomains: readonly string[] | null;
  readonly deletionHours: number | null;
  readonly allowedSendTypes: readonly SendItemType[];
  readonly malformed: boolean;
}

export interface RestrictedItemTypePolicy {
  readonly organizationId: string | null;
  readonly restrictedTypes: readonly number[];
  readonly restrictAllTypes: boolean;
  readonly malformed: boolean;
}

export interface EffectiveUriMatchDefaultsPolicy {
  readonly organizationId: string | null;
  readonly malformed: boolean;
  readonly value: UriMatchStrategySetting;
}

/** One strictly validated ODO policy that may transfer existing personal items. */
export interface EffectiveOrganizationDataOwnershipTransferPolicy {
  readonly organizationId: string;
  /** Vaultwarden currently emits null; only a sole undated candidate is unambiguous. */
  readonly revisionDate: string | null;
}

export interface EnterprisePolicyScope {
  readonly serverGeneration: number;
  readonly accountGeneration: number;
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly rawGeneration: string;
}

export interface EffectiveEnterprisePolicySnapshot {
  readonly scope: EnterprisePolicyScope;
  readonly policySource: EnterprisePolicySource;
  readonly organizationContextSource: OrganizationContextSource;
  readonly activePolicyTypes: readonly SupportedEnterprisePolicyType[];
  readonly malformedPolicyTypes: readonly SupportedEnterprisePolicyType[];
  readonly unknownPolicyTypes: readonly number[];
  /** Require SSO is an enabled-only policy; malformed applicable entries fail closed. */
  readonly requireSso: boolean;
  readonly organizationDataOwnershipRequired: boolean;
  readonly organizationDataOwnershipTransferPolicy:
    EffectiveOrganizationDataOwnershipTransferPolicy | null;
  /** Compatibility projection of the selected transfer target (zero or one organization). */
  readonly organizationDataOwnershipOrganizationIds: readonly string[];
  readonly personalVaultExportDisabled: boolean;
  readonly activateAutofillRequired: boolean;
  readonly unlockWithPinRemoved: boolean;
  readonly maximumVaultTimeoutPolicy: EffectiveMaximumVaultTimeoutPolicy | null;
  readonly knownOrganizationIds: readonly string[];
  readonly restrictedItemTypePolicies: readonly RestrictedItemTypePolicy[];
  readonly restrictedItemTypes: readonly number[];
  readonly sendControls: EffectiveSendControls;
  readonly masterPasswordPolicy: MasterPasswordPolicy | null;
  readonly masterPasswordPolicyMalformed: boolean;
  readonly passwordGeneratorPolicy: EffectivePasswordGeneratorPolicy | null;
  readonly uriMatchDefaultsPolicy: EffectiveUriMatchDefaultsPolicy | null;
}

export interface DeriveEnterprisePolicyInput {
  readonly response: SyncResponse;
  readonly accountLease: AccountLease;
  readonly rawGeneration: string;
}

export interface EnterpriseItemSubject {
  readonly type: number;
  readonly organizationId?: string | null;
}

export interface EnterpriseSendSubject {
  readonly type: number;
  readonly hideEmail?: boolean;
}

const POLICY_LEASE_OWNER: unique symbol = Symbol('enterprisePolicyLeaseOwner');

export interface PolicyLease extends EnterprisePolicyScope {
  readonly generation: number;
}

interface OwnedPolicyLease extends PolicyLease {
  readonly [POLICY_LEASE_OWNER]: symbol;
}

interface OrganizationPolicyContext {
  readonly id: string;
  readonly status: unknown;
  readonly role: unknown;
  readonly enabled: unknown;
  readonly usePolicies: unknown;
  readonly isProviderUser: boolean;
}

interface EvaluatedPolicy {
  readonly type: SupportedEnterprisePolicyType;
  readonly organizationId: string | null;
  readonly data: unknown;
  readonly revisionDate: unknown;
}

type ParsedOrganizationDataOwnershipTransfer =
  | { readonly kind: 'none' }
  | { readonly kind: 'malformed' }
  | {
      readonly kind: 'candidate';
      readonly policy: EffectiveOrganizationDataOwnershipTransferPolicy;
      readonly revisionOrder: string | null;
    };

interface ParsedSendControls {
  readonly disableSend: boolean;
  readonly disableHideEmail: boolean;
  readonly whoCanAccess?: SendWhoCanAccess;
  readonly allowedDomains?: string;
  readonly deletionHours?: number;
  readonly allowedSendTypes?: readonly SendItemType[];
}

const SUPPORTED_POLICY_TYPES = new Set<number>(Object.values(EnterprisePolicyType));
const DEFAULT_SEND_TYPES = Object.freeze([0, 1] as const);
const FAIL_CLOSED_TIMEOUT = Object.freeze<MaximumVaultTimeoutPolicyData>({
  type: 'immediately',
  minutes: 0,
  action: 'logOut',
});
const DEFAULT_CARD_TYPE = 3;

const EXEMPT_ROLES = new Map<SupportedEnterprisePolicyType, readonly number[]>([
  [EnterprisePolicyType.MasterPassword, []],
  [EnterprisePolicyType.PasswordGenerator, []],
  [EnterprisePolicyType.RequireSso, [0, 1]],
  [EnterprisePolicyType.OrganizationDataOwnership, [0, 1]],
  [EnterprisePolicyType.DisableSend, [0, 1]],
  [EnterprisePolicyType.SendOptions, [0, 1]],
  [EnterprisePolicyType.MaximumVaultTimeout, [0]],
  [EnterprisePolicyType.DisablePersonalVaultExport, [0, 1]],
  [EnterprisePolicyType.ActivateAutofill, [0, 1]],
  [EnterprisePolicyType.RemoveUnlockWithPin, []],
  [EnterprisePolicyType.RestrictedItemTypes, []],
  [EnterprisePolicyType.UriMatchDefaults, [0, 1]],
  [EnterprisePolicyType.SendControls, [0, 1]],
]);
const PROVIDER_EXEMPT_POLICY_TYPES = new Set<SupportedEnterprisePolicyType>([
  EnterprisePolicyType.MasterPassword,
  EnterprisePolicyType.PasswordGenerator,
  EnterprisePolicyType.RequireSso,
  EnterprisePolicyType.OrganizationDataOwnership,
  EnterprisePolicyType.DisableSend,
  EnterprisePolicyType.SendOptions,
  EnterprisePolicyType.MaximumVaultTimeout,
  EnterprisePolicyType.DisablePersonalVaultExport,
  EnterprisePolicyType.ActivateAutofill,
  EnterprisePolicyType.RemoveUnlockWithPin,
  EnterprisePolicyType.RestrictedItemTypes,
  EnterprisePolicyType.UriMatchDefaults,
  EnterprisePolicyType.SendControls,
]);

/** Derive an immutable policy snapshot from one encrypted raw sync generation. */
export function deriveEffectiveEnterprisePolicy(
  input: DeriveEnterprisePolicyInput,
): EffectiveEnterprisePolicySnapshot {
  const scope = freezeScope(input.accountLease, input.rawGeneration);
  const selectedPolicies = selectPolicies(input.response);
  const organizationContexts = collectOrganizationContexts(input.response);
  const active: EvaluatedPolicy[] = [];
  const unknownPolicyTypes: number[] = [];
  const malformedPolicyTypes: SupportedEnterprisePolicyType[] = [];
  let malformedApplicableRequireSso = false;

  for (const rawPolicy of selectedPolicies.values) {
    const policyType = ownDataProperty(rawPolicy, 'type');
    if (!isRecord(rawPolicy) || !Number.isSafeInteger(policyType)) {
      if (policyType === EnterprisePolicyType.RequireSso) {
        malformedPolicyTypes.push(EnterprisePolicyType.RequireSso);
        if (ownDataProperty(rawPolicy, 'enabled') !== false) {
          malformedApplicableRequireSso ||= requireSsoCouldApply(
            rawPolicy,
            organizationContexts.contexts,
          );
        }
        continue;
      }
      throw new TypeError('Enterprise policy envelope is invalid');
    }
    const numericPolicyType = policyType as number;
    if (!SUPPORTED_POLICY_TYPES.has(numericPolicyType)) {
      if (numericPolicyType >= 0) unknownPolicyTypes.push(numericPolicyType);
      continue;
    }
    const type = numericPolicyType as SupportedEnterprisePolicyType;
    const enabled = ownDataProperty(rawPolicy, 'enabled');
    if (enabled === false) continue;

    const rawOrganizationId = ownDataProperty(rawPolicy, 'organizationId');
    const organizationId = type === EnterprisePolicyType.RequireSso
      ? strictPolicyIdentifier(rawOrganizationId)
      : nonEmptyString(rawOrganizationId);
    const context = organizationId === null
      ? undefined
      : organizationContexts.contexts.get(organizationId);
    const applies = policyApplies(type, context);

    if (enabled !== true) {
      malformedPolicyTypes.push(type);
      if (type === EnterprisePolicyType.RequireSso && applies) {
        malformedApplicableRequireSso = true;
      }
      continue;
    }
    if (!applies) continue;

    if (type === EnterprisePolicyType.RequireSso && !isStrictRequireSsoEnvelope(rawPolicy)) {
      malformedPolicyTypes.push(type);
      malformedApplicableRequireSso = true;
      continue;
    }
    active.push(Object.freeze({
      type,
      organizationId,
      data: ownDataProperty(rawPolicy, 'data'),
      revisionDate: ownDataProperty(rawPolicy, 'revisionDate'),
    }));
  }

  const activePolicyTypes = uniqueSorted(active.map((policy) => policy.type));

  const requireSsoPolicies = active.filter(
    (policy) => policy.type === EnterprisePolicyType.RequireSso,
  );
  for (const policy of requireSsoPolicies) {
    if (policy.data !== null && policy.data !== undefined) {
      malformedPolicyTypes.push(EnterprisePolicyType.RequireSso);
    }
  }
  const requireSso = malformedApplicableRequireSso || requireSsoPolicies.length > 0;

  const organizationDataOwnershipPolicies = active.filter(
    (policy) => policy.type === EnterprisePolicyType.OrganizationDataOwnership,
  );
  const organizationDataOwnershipTransferCandidates: Array<Extract<
    ParsedOrganizationDataOwnershipTransfer,
    { readonly kind: 'candidate' }
  >> = [];
  for (const policy of organizationDataOwnershipPolicies) {
    const parsed = parseOrganizationDataOwnershipTransferPolicy(
      policy,
      organizationContexts.contexts,
    );
    if (parsed.kind === 'malformed') {
      malformedPolicyTypes.push(EnterprisePolicyType.OrganizationDataOwnership);
    } else if (parsed.kind === 'candidate') {
      organizationDataOwnershipTransferCandidates.push(parsed);
    }
  }
  const hasUndatedTransfer = organizationDataOwnershipTransferCandidates.some(
    (candidate) => candidate.revisionOrder === null,
  );
  let organizationDataOwnershipTransferPolicy: EffectiveOrganizationDataOwnershipTransferPolicy | null;
  if (malformedPolicyTypes.includes(EnterprisePolicyType.OrganizationDataOwnership)
      || (hasUndatedTransfer && organizationDataOwnershipTransferCandidates.length !== 1)) {
    malformedPolicyTypes.push(EnterprisePolicyType.OrganizationDataOwnership);
    organizationDataOwnershipTransferPolicy = null;
  } else {
    organizationDataOwnershipTransferCandidates.sort(compareOrganizationDataOwnershipTransfers);
    organizationDataOwnershipTransferPolicy =
      organizationDataOwnershipTransferCandidates[0]?.policy ?? null;
  }

  const masterPasswordPolicies: MasterPasswordPolicy[] = [];
  let masterPasswordPolicyMalformed = false;
  for (const policy of active.filter((entry) => entry.type === EnterprisePolicyType.MasterPassword)) {
    try {
      const parsed = parseMasterPasswordPolicy(policy.data);
      if (parsed) masterPasswordPolicies.push(parsed);
    } catch {
      masterPasswordPolicyMalformed = true;
      malformedPolicyTypes.push(EnterprisePolicyType.MasterPassword);
    }
  }
  const masterPasswordPolicy = masterPasswordPolicyMalformed
    ? null
    : combineMasterPasswordPolicies(masterPasswordPolicies);

  const rawPasswordGeneratorPolicies = active.filter(
    (policy) => policy.type === EnterprisePolicyType.PasswordGenerator,
  );
  const parsedPasswordGeneratorPolicies: PasswordGeneratorPolicyData[] = [];
  let malformedPasswordGeneratorPolicy = false;
  for (const policy of rawPasswordGeneratorPolicies) {
    const parsed = parsePasswordGeneratorPolicyData(policy.data);
    if (parsed === null) {
      malformedPasswordGeneratorPolicy = true;
      malformedPolicyTypes.push(EnterprisePolicyType.PasswordGenerator);
    } else {
      parsedPasswordGeneratorPolicies.push(parsed);
    }
  }
  const passwordGeneratorPolicy: EffectivePasswordGeneratorPolicy | null =
    rawPasswordGeneratorPolicies.length === 0
      ? null
      : Object.freeze({
          malformed: malformedPasswordGeneratorPolicy,
          data: combinePasswordGeneratorPolicyData(parsedPasswordGeneratorPolicies),
        });

  const rawUriMatchDefaults = active.find(
    (policy) => policy.type === EnterprisePolicyType.UriMatchDefaults,
  );
  let uriMatchDefaultsPolicy: EffectiveUriMatchDefaultsPolicy | null = null;
  if (rawUriMatchDefaults) {
    const value = parseUriMatchDefaults(rawUriMatchDefaults.data);
    const malformed = value === null;
    if (malformed) malformedPolicyTypes.push(EnterprisePolicyType.UriMatchDefaults);
    uriMatchDefaultsPolicy = Object.freeze({
      organizationId: rawUriMatchDefaults.organizationId,
      malformed,
      value: value ?? UriMatchStrategy.Never,
    });
  }

  const rawMaximumVaultTimeout = active.find(
    (policy) => policy.type === EnterprisePolicyType.MaximumVaultTimeout,
  );
  let maximumVaultTimeoutPolicy: EffectiveMaximumVaultTimeoutPolicy | null = null;
  if (rawMaximumVaultTimeout) {
    const data = parseMaximumVaultTimeout(rawMaximumVaultTimeout.data);
    if (data === null) {
      malformedPolicyTypes.push(EnterprisePolicyType.MaximumVaultTimeout);
      maximumVaultTimeoutPolicy = Object.freeze({
        organizationId: rawMaximumVaultTimeout.organizationId,
        malformed: true,
        data: FAIL_CLOSED_TIMEOUT,
      });
    } else {
      maximumVaultTimeoutPolicy = Object.freeze({
        organizationId: rawMaximumVaultTimeout.organizationId,
        malformed: false,
        data,
      });
    }
  }

  const restrictedItemTypePolicies = active
    .filter((policy) => policy.type === EnterprisePolicyType.RestrictedItemTypes)
    .map((policy) => {
      const restriction = parseRestrictedItemTypes(policy.data);
      if (restriction.malformed) {
        malformedPolicyTypes.push(EnterprisePolicyType.RestrictedItemTypes);
      }
      return Object.freeze({
        organizationId: policy.organizationId,
        restrictedTypes: restriction.restrictedTypes,
        restrictAllTypes: restriction.restrictAllTypes,
        malformed: restriction.malformed,
      });
    });

  const sendPolicies = active.filter((policy) => policy.type === EnterprisePolicyType.SendControls);
  const parsedSendPolicies: ParsedSendControls[] = [];
  let malformedSendControls = false;
  for (const policy of sendPolicies) {
    const parsed = parseSendControls(policy.data);
    if (parsed === null) {
      malformedSendControls = true;
      malformedPolicyTypes.push(EnterprisePolicyType.SendControls);
    } else {
      parsedSendPolicies.push(parsed);
    }
  }

  let legacyDisableHideEmail = false;
  let malformedLegacySendOptions = false;
  for (const policy of active.filter((entry) => entry.type === EnterprisePolicyType.SendOptions)) {
    const disableHideEmail = parseLegacySendOptions(policy.data);
    if (disableHideEmail === null) {
      malformedLegacySendOptions = true;
      malformedPolicyTypes.push(EnterprisePolicyType.SendOptions);
    } else {
      legacyDisableHideEmail ||= disableHideEmail;
    }
  }

  const legacyDisableSend = active.some((policy) => policy.type === EnterprisePolicyType.DisableSend);
  const sendControls = combineSendControls(
    parsedSendPolicies,
    legacyDisableSend,
    legacyDisableHideEmail,
    malformedSendControls,
    malformedLegacySendOptions,
  );

  return Object.freeze({
    scope,
    policySource: selectedPolicies.source,
    organizationContextSource: organizationContexts.source,
    activePolicyTypes: Object.freeze(activePolicyTypes),
    malformedPolicyTypes: Object.freeze(uniqueSorted(malformedPolicyTypes)),
    unknownPolicyTypes: Object.freeze(uniqueSorted(unknownPolicyTypes)),
    requireSso,
    organizationDataOwnershipRequired: organizationDataOwnershipPolicies.length > 0
      || malformedPolicyTypes.includes(EnterprisePolicyType.OrganizationDataOwnership),
    organizationDataOwnershipTransferPolicy,
    organizationDataOwnershipOrganizationIds: Object.freeze(
      organizationDataOwnershipTransferPolicy
        ? [organizationDataOwnershipTransferPolicy.organizationId]
        : [],
    ),
    personalVaultExportDisabled: active.some(
      (policy) => policy.type === EnterprisePolicyType.DisablePersonalVaultExport,
    ),
    activateAutofillRequired: active.some(
      (policy) => policy.type === EnterprisePolicyType.ActivateAutofill,
    ),
    unlockWithPinRemoved: active.some(
      (policy) => policy.type === EnterprisePolicyType.RemoveUnlockWithPin,
    ),
    maximumVaultTimeoutPolicy,
    knownOrganizationIds: Object.freeze(uniqueSortedStrings([...organizationContexts.contexts.keys()])),
    restrictedItemTypePolicies: Object.freeze(restrictedItemTypePolicies),
    restrictedItemTypes: Object.freeze(uniqueSorted(restrictedItemTypePolicies.flatMap(
      (policy) => policy.restrictedTypes,
    ))),
    sendControls,
    masterPasswordPolicy,
    masterPasswordPolicyMalformed,
    passwordGeneratorPolicy,
    uriMatchDefaultsPolicy,
  });
}

export function enterprisePolicyAllows(
  snapshot: EffectiveEnterprisePolicySnapshot,
  capability: EnterprisePolicyCapability,
): boolean {
  switch (capability) {
    case 'createPersonalVaultItem':
      return !snapshot.organizationDataOwnershipRequired;
    case 'createOrEditSend':
      return !snapshot.sendControls.disabled;
    case 'exportPersonalVault':
      return !snapshot.personalVaultExportDisabled
        && !snapshot.organizationDataOwnershipRequired;
    case 'unlockWithPin':
      return !snapshot.unlockWithPinRemoved;
  }
}

/** Match official restricted-item behavior: personal items use the union; org items use that org. */
export function isEnterpriseItemRestricted(
  snapshot: EffectiveEnterprisePolicySnapshot,
  subject: EnterpriseItemSubject,
): boolean {
  if (!isRawCipherType(subject.type)) return true;
  const organizationId = nonEmptyString(subject.organizationId);
  const typeIsRestricted = snapshot.restrictedItemTypePolicies.some(
    (policy) => policy.restrictAllTypes || policy.restrictedTypes.includes(subject.type),
  );
  if (!typeIsRestricted) return false;
  if (organizationId === null) return true;
  if (!snapshot.knownOrganizationIds.includes(organizationId)) return true;
  return snapshot.restrictedItemTypePolicies.some((policy) => (
    policy.organizationId === null || policy.organizationId === organizationId
  ) && (policy.restrictAllTypes || policy.restrictedTypes.includes(subject.type)));
}

export function enterprisePolicyAllowsSend(
  snapshot: EffectiveEnterprisePolicySnapshot,
  subject: EnterpriseSendSubject,
): boolean {
  if (snapshot.sendControls.disabled || !isSendItemType(subject.type)) return false;
  if (subject.hideEmail === true && snapshot.sendControls.disableHideEmail) return false;
  return snapshot.sendControls.allowedSendTypes.includes(subject.type);
}

/** In-memory revocation fence for decisions tied to an account and raw-sync generation. */
export class EnterprisePolicyGate {
  readonly #owner = Symbol('enterprisePolicyGate');
  readonly #issued = new WeakSet<object>();
  #generation = 0;
  #snapshot: EffectiveEnterprisePolicySnapshot | undefined;

  replace(input: DeriveEnterprisePolicyInput): EffectiveEnterprisePolicySnapshot {
    this.#generation += 1;
    this.#snapshot = undefined;
    const snapshot = deriveEffectiveEnterprisePolicy(input);
    this.#snapshot = snapshot;
    return snapshot;
  }

  invalidate(): void {
    this.#generation += 1;
    this.#snapshot = undefined;
  }

  capture(): PolicyLease {
    const snapshot = this.#snapshot;
    if (!snapshot) {
      throw new AppError('sync_required', 'Enterprise policy state is unavailable.');
    }
    const lease = Object.freeze({
      ...snapshot.scope,
      generation: this.#generation,
      [POLICY_LEASE_OWNER]: this.#owner,
    });
    this.#issued.add(lease);
    return lease;
  }

  assert(lease: PolicyLease): EffectiveEnterprisePolicySnapshot {
    const owned = lease as Partial<OwnedPolicyLease>;
    const snapshot = this.#snapshot;
    if (
      !isRecord(lease)
      || !this.#issued.has(lease)
      || owned[POLICY_LEASE_OWNER] !== this.#owner
      || lease.generation !== this.#generation
      || !snapshot
      || !sameScope(lease, snapshot.scope)
    ) {
      throw new AppError('denied', 'Enterprise policy state changed during the operation.');
    }
    return snapshot;
  }

  isCurrent(lease: PolicyLease): boolean {
    try {
      this.assert(lease);
      return true;
    } catch {
      return false;
    }
  }

  allows(lease: PolicyLease, capability: EnterprisePolicyCapability): boolean {
    return enterprisePolicyAllows(this.assert(lease), capability);
  }

  assertAllowed(lease: PolicyLease, capability: EnterprisePolicyCapability): void {
    if (!this.allows(lease, capability)) {
      throw new AppError('denied', `Enterprise policy denies ${capability}.`);
    }
  }

  isItemRestricted(lease: PolicyLease, subject: EnterpriseItemSubject): boolean {
    return isEnterpriseItemRestricted(this.assert(lease), subject);
  }

  allowsSend(lease: PolicyLease, subject: EnterpriseSendSubject): boolean {
    return enterprisePolicyAllowsSend(this.assert(lease), subject);
  }

  getMaximumVaultTimeoutPolicy(
    lease: PolicyLease,
  ): EffectiveMaximumVaultTimeoutPolicy | null {
    return this.assert(lease).maximumVaultTimeoutPolicy;
  }

  getSendControls(lease: PolicyLease): EffectiveSendControls {
    return this.assert(lease).sendControls;
  }

  getRestrictedItemTypes(lease: PolicyLease): readonly number[] {
    return this.assert(lease).restrictedItemTypes;
  }

  getPasswordGeneratorPolicy(lease: PolicyLease): EffectivePasswordGeneratorPolicy | null {
    return this.assert(lease).passwordGeneratorPolicy;
  }

  getActivateAutofillRequired(lease: PolicyLease): boolean {
    return this.assert(lease).activateAutofillRequired;
  }

  getRequireSso(lease: PolicyLease): boolean {
    return this.assert(lease).requireSso;
  }

  getUriMatchDefaultsPolicy(lease: PolicyLease): EffectiveUriMatchDefaultsPolicy | null {
    return this.assert(lease).uriMatchDefaultsPolicy;
  }

  getOrganizationDataOwnershipTransferPolicy(
    lease: PolicyLease,
  ): EffectiveOrganizationDataOwnershipTransferPolicy | null {
    return this.assert(lease).organizationDataOwnershipTransferPolicy;
  }

  inspect(lease: PolicyLease): EffectiveEnterprisePolicySnapshot {
    return this.assert(lease);
  }
}

function selectPolicies(response: SyncResponse): {
  readonly source: EnterprisePolicySource;
  readonly values: readonly unknown[];
} {
  if (response.policiesNew !== undefined
      && response.policiesNew !== null
      && !Array.isArray(response.policiesNew)) {
    throw new TypeError('Authoritative enterprise policy collection is invalid');
  }
  if (Array.isArray(response.policiesNew) && response.policiesNew.length > 0) {
    return { source: 'policiesNew', values: response.policiesNew };
  }
  if (response.policies !== undefined
      && response.policies !== null
      && !Array.isArray(response.policies)) {
    throw new TypeError('Legacy enterprise policy collection is invalid');
  }
  if (Array.isArray(response.policies)) return { source: 'policies', values: response.policies };
  return { source: 'none', values: [] };
}

function collectOrganizationContexts(response: SyncResponse): {
  readonly source: OrganizationContextSource;
  readonly contexts: ReadonlyMap<string, OrganizationPolicyContext>;
} {
  const hasOrganizationsNew = response.profile.organizationsNew !== null
    && response.profile.organizationsNew !== undefined;
  const organizations = hasOrganizationsNew
    ? Array.isArray(response.profile.organizationsNew) ? response.profile.organizationsNew : []
    : Array.isArray(response.profile.organizations) ? response.profile.organizations : [];
  const source: OrganizationContextSource = hasOrganizationsNew
    ? 'organizationsNew'
    : Array.isArray(response.profile.organizations) ? 'organizations' : 'none';
  const contexts = new Map<string, OrganizationPolicyContext>();

  for (const organization of organizations) {
    const context = organizationContext(organization, false);
    if (context) contexts.set(context.id, context);
  }
  if (Array.isArray(response.profile.providerOrganizations)) {
    for (const organization of response.profile.providerOrganizations) {
      const providerContext = organizationContext(organization, true);
      if (!providerContext) continue;
      const directContext = contexts.get(providerContext.id);
      contexts.set(providerContext.id, directContext
        ? Object.freeze({ ...directContext, isProviderUser: true })
        : providerContext);
    }
  }
  return { source, contexts };
}

function organizationContext(
  organization: OrganizationResponse,
  isProviderUser: boolean,
): OrganizationPolicyContext | null {
  if (!isRecord(organization)) return null;
  const id = nonEmptyString(organization.id);
  if (id === null) return null;
  return Object.freeze({
    id,
    status: organization.status,
    role: organization.type,
    enabled: organization.enabled,
    usePolicies: organization.usePolicies,
    isProviderUser,
  });
}

function policyApplies(
  type: SupportedEnterprisePolicyType,
  context: OrganizationPolicyContext | undefined,
): boolean {
  if (!context) return true;
  if (context.enabled === false || context.usePolicies === false) return false;
  if (isKnownMembershipStatus(context.status) && context.status !== 1 && context.status !== 2) {
    return false;
  }
  if (context.isProviderUser && PROVIDER_EXEMPT_POLICY_TYPES.has(type)) return false;
  if (isKnownOrganizationRole(context.role)
    && EXEMPT_ROLES.get(type)?.includes(context.role) === true) return false;
  // Legacy self-hosted membership records may omit entitlement flags. A present context keeps its
  // status/role/provider exemptions; only non-exempt users are treated as implicitly enabled.
  return true;
}

function requireSsoCouldApply(
  rawPolicy: unknown,
  contexts: ReadonlyMap<string, OrganizationPolicyContext>,
): boolean {
  const organizationId = strictPolicyIdentifier(ownDataProperty(rawPolicy, 'organizationId'));
  return policyApplies(
    EnterprisePolicyType.RequireSso,
    organizationId === null ? undefined : contexts.get(organizationId),
  );
}

function isStrictRequireSsoEnvelope(value: Record<string, unknown>): boolean {
  if (!hasOnlyOwnDataProperties(value)) return false;
  return strictPolicyIdentifier(ownDataProperty(value, 'id')) !== null
    && strictPolicyIdentifier(ownDataProperty(value, 'organizationId')) !== null
    && ownDataProperty(value, 'type') === EnterprisePolicyType.RequireSso
    && typeof ownDataProperty(value, 'enabled') === 'boolean';
}

function parseMaximumVaultTimeout(data: unknown): MaximumVaultTimeoutPolicyData | null {
  if (!isRecord(data) || !Number.isSafeInteger(data.minutes) || (data.minutes as number) < 0) {
    return null;
  }
  const type = data.type === undefined ? null : data.type;
  const action = data.action === undefined ? null : data.action;
  if (!isMaximumVaultTimeoutType(type) || !isMaximumVaultTimeoutAction(action)) return null;
  return Object.freeze({ type, minutes: data.minutes as number, action });
}

function parseOrganizationDataOwnershipTransferPolicy(
  policy: EvaluatedPolicy,
  organizationContexts: ReadonlyMap<string, OrganizationPolicyContext>,
): ParsedOrganizationDataOwnershipTransfer {
  if (policy.data === null || policy.data === undefined) return { kind: 'none' };
  if (!isRecord(policy.data)) return { kind: 'malformed' };
  const keys = Object.keys(policy.data);
  if (keys.length !== 1 || keys[0] !== 'enableIndividualItemsTransfer') {
    return { kind: 'malformed' };
  }
  const enabled = policy.data.enableIndividualItemsTransfer;
  if (typeof enabled !== 'boolean') return { kind: 'malformed' };
  if (!enabled) return { kind: 'none' };

  const organizationId = strictPolicyIdentifier(policy.organizationId);
  if (
    organizationId === null
    || !organizationContexts.has(organizationId)
  ) return { kind: 'malformed' };
  if (policy.revisionDate === null) {
    return Object.freeze({
      kind: 'candidate',
      policy: Object.freeze({ organizationId, revisionDate: null }),
      revisionOrder: null,
    });
  }
  const revision = strictPolicyRevisionDate(policy.revisionDate);
  if (revision === null) return { kind: 'malformed' };
  return Object.freeze({
    kind: 'candidate',
    policy: Object.freeze({
      organizationId,
      revisionDate: revision.value,
    }),
    revisionOrder: revision.order,
  });
}

function compareOrganizationDataOwnershipTransfers(
  left: Extract<ParsedOrganizationDataOwnershipTransfer, { readonly kind: 'candidate' }>,
  right: Extract<ParsedOrganizationDataOwnershipTransfer, { readonly kind: 'candidate' }>,
): number {
  if (left.revisionOrder === null) return right.revisionOrder === null ? 0 : -1;
  if (right.revisionOrder === null) return 1;
  if (left.revisionOrder < right.revisionOrder) return -1;
  if (left.revisionOrder > right.revisionOrder) return 1;
  if (left.policy.organizationId < right.policy.organizationId) return -1;
  if (left.policy.organizationId > right.policy.organizationId) return 1;
  return 0;
}

function strictPolicyIdentifier(value: unknown): string | null {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 4_096
    || value !== value.trim()
  ) return null;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return null;
  }
  return value;
}

function strictPolicyRevisionDate(value: unknown): {
  readonly value: string;
  readonly order: string;
} | null {
  if (typeof value !== 'string') return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?Z$/.exec(value);
  if (!match) return null;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const fraction = match[7] ?? '';
  const millisecond = Number(fraction.padEnd(3, '0').slice(0, 3));
  const date = new Date(0);
  date.setUTCFullYear(year!, month! - 1, day!);
  date.setUTCHours(hour!, minute!, second!, millisecond);
  if (
    date.getUTCFullYear() !== year
    || date.getUTCMonth() !== month! - 1
    || date.getUTCDate() !== day
    || date.getUTCHours() !== hour
    || date.getUTCMinutes() !== minute
    || date.getUTCSeconds() !== second
    || date.getUTCMilliseconds() !== millisecond
  ) return null;
  return Object.freeze({
    value,
    order: `${value.slice(0, 19)}.${fraction.padEnd(7, '0')}Z`,
  });
}

function parseUriMatchDefaults(data: unknown): UriMatchStrategySetting | null {
  if (!isRecord(data)) return null;
  return isUriMatchStrategySetting(data.uriMatchDetection) ? data.uriMatchDetection : null;
}

function parseRestrictedItemTypes(data: unknown): {
  readonly restrictedTypes: readonly number[];
  readonly restrictAllTypes: boolean;
  readonly malformed: boolean;
} {
  if (data === null || data === undefined) {
    return Object.freeze({
      restrictedTypes: Object.freeze([DEFAULT_CARD_TYPE]),
      restrictAllTypes: false,
      malformed: false,
    });
  }
  if (!Array.isArray(data) || !data.every(isRawCipherType)) {
    return Object.freeze({
      restrictedTypes: Object.freeze([]),
      restrictAllTypes: true,
      malformed: true,
    });
  }
  return Object.freeze({
    restrictedTypes: Object.freeze(uniqueSorted(data)),
    restrictAllTypes: false,
    malformed: false,
  });
}

function parseSendControls(data: unknown): ParsedSendControls | null {
  if (data === null || data === undefined) {
    return Object.freeze({ disableSend: false, disableHideEmail: false });
  }
  if (!isRecord(data)) return null;
  if (data.disableSend !== undefined && typeof data.disableSend !== 'boolean') return null;
  if (data.disableHideEmail !== undefined && typeof data.disableHideEmail !== 'boolean') return null;
  if (data.whoCanAccess !== undefined
    && data.whoCanAccess !== null
    && !isSendWhoCanAccess(data.whoCanAccess)) return null;
  if (data.allowedDomains !== undefined
    && data.allowedDomains !== null
    && typeof data.allowedDomains !== 'string') return null;
  if (data.deletionHours !== undefined
    && data.deletionHours !== null
    && (!Number.isSafeInteger(data.deletionHours) || (data.deletionHours as number) <= 0)) return null;
  if (data.allowedSendTypes !== undefined && data.allowedSendTypes !== null) {
    if (!Array.isArray(data.allowedSendTypes)
      || data.allowedSendTypes.length === 0
      || !data.allowedSendTypes.every(isSendItemType)) return null;
  }

  return Object.freeze({
    disableSend: data.disableSend === true,
    disableHideEmail: data.disableHideEmail === true,
    ...(isSendWhoCanAccess(data.whoCanAccess) ? { whoCanAccess: data.whoCanAccess } : {}),
    ...(typeof data.allowedDomains === 'string' ? { allowedDomains: data.allowedDomains } : {}),
    ...(typeof data.deletionHours === 'number' ? { deletionHours: data.deletionHours } : {}),
    ...(Array.isArray(data.allowedSendTypes)
      ? { allowedSendTypes: Object.freeze(uniqueSorted(data.allowedSendTypes as SendItemType[])) }
      : {}),
  });
}

function parseLegacySendOptions(data: unknown): boolean | null {
  if (data === null || data === undefined) return false;
  if (!isRecord(data)) return null;
  if (data.disableHideEmail !== undefined && typeof data.disableHideEmail !== 'boolean') return null;
  return data.disableHideEmail === true;
}

function combineSendControls(
  policies: readonly ParsedSendControls[],
  legacyDisableSend: boolean,
  legacyDisableHideEmail: boolean,
  malformedSendControls: boolean,
  malformedLegacySendOptions: boolean,
): EffectiveSendControls {
  if (malformedSendControls) {
    return Object.freeze({
      disabled: true,
      disableHideEmail: true,
      whoCanAccess: 2,
      allowedDomains: Object.freeze([]),
      deletionHours: 1,
      allowedSendTypes: Object.freeze([]),
      malformed: true,
    });
  }

  const explicitSendTypes = uniqueSorted(policies.flatMap(
    (policy) => policy.allowedSendTypes ?? [],
  )) as SendItemType[];
  const domains = policies.find((policy) => policy.allowedDomains?.trim())?.allowedDomains;
  return Object.freeze({
    disabled: legacyDisableSend || policies.some((policy) => policy.disableSend),
    disableHideEmail: legacyDisableHideEmail
      || malformedLegacySendOptions
      || policies.some((policy) => policy.disableHideEmail),
    whoCanAccess: policies.find((policy) => policy.whoCanAccess !== undefined)?.whoCanAccess ?? 0,
    allowedDomains: domains === undefined
      ? null
      : Object.freeze(domains.split(',').map((domain) => domain.trim().toLowerCase()).filter(Boolean)),
    deletionHours: policies.find((policy) => policy.deletionHours !== undefined)?.deletionHours ?? null,
    allowedSendTypes: Object.freeze(explicitSendTypes.length > 0
      ? explicitSendTypes
      : [...DEFAULT_SEND_TYPES]),
    malformed: malformedLegacySendOptions,
  });
}

function combineMasterPasswordPolicies(
  policies: readonly MasterPasswordPolicy[],
): MasterPasswordPolicy | null {
  if (policies.length === 0) return null;
  return Object.freeze({
    minComplexity: Math.max(...policies.map((policy) => policy.minComplexity)),
    minLength: Math.max(...policies.map((policy) => policy.minLength)),
    requireUpper: policies.some((policy) => policy.requireUpper),
    requireLower: policies.some((policy) => policy.requireLower),
    requireNumbers: policies.some((policy) => policy.requireNumbers),
    requireSpecial: policies.some((policy) => policy.requireSpecial),
    enforceOnLogin: policies.some((policy) => policy.enforceOnLogin),
  });
}

function freezeScope(accountLease: AccountLease, rawGeneration: string): EnterprisePolicyScope {
  if (!Number.isSafeInteger(accountLease.serverGeneration) || accountLease.serverGeneration < 0
    || !Number.isSafeInteger(accountLease.accountGeneration) || accountLease.accountGeneration < 0
    || nonEmptyString(accountLease.serverUrl) === null
    || nonEmptyString(accountLease.accountIdentity) === null
    || nonEmptyString(rawGeneration) === null) {
    throw new RangeError('Enterprise policy scope must identify one account and raw generation.');
  }
  return Object.freeze({
    serverGeneration: accountLease.serverGeneration,
    accountGeneration: accountLease.accountGeneration,
    serverUrl: accountLease.serverUrl,
    accountIdentity: accountLease.accountIdentity,
    rawGeneration,
  });
}

function sameScope(left: EnterprisePolicyScope, right: EnterprisePolicyScope): boolean {
  return left.serverGeneration === right.serverGeneration
    && left.accountGeneration === right.accountGeneration
    && left.serverUrl === right.serverUrl
    && left.accountIdentity === right.accountIdentity
    && left.rawGeneration === right.rawGeneration;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function ownDataProperty(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function hasOnlyOwnDataProperties(value: Record<string, unknown>): boolean {
  return Reflect.ownKeys(value).every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return typeof key === 'string'
      && descriptor !== undefined
      && descriptor.enumerable
      && 'value' in descriptor;
  });
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value : null;
}

function isKnownMembershipStatus(value: unknown): value is -1 | 0 | 1 | 2 | 3 {
  return value === -1 || value === 0 || value === 1 || value === 2 || value === 3;
}

function isKnownOrganizationRole(value: unknown): value is 0 | 1 | 2 | 4 {
  return value === 0 || value === 1 || value === 2 || value === 4;
}

function isMaximumVaultTimeoutType(value: unknown): value is MaximumVaultTimeoutType {
  return value === null
    || value === 'never'
    || value === 'onAppRestart'
    || value === 'onSystemLock'
    || value === 'immediately'
    || value === 'custom';
}

function isMaximumVaultTimeoutAction(value: unknown): value is MaximumVaultTimeoutAction {
  return value === null || value === 'lock' || value === 'logOut';
}

function isSendWhoCanAccess(value: unknown): value is SendWhoCanAccess {
  return value === 0 || value === 1 || value === 2;
}

function isSendItemType(value: unknown): value is SendItemType {
  return value === 0 || value === 1;
}

function isRawCipherType(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function uniqueSorted<T extends number>(values: readonly T[]): T[] {
  return [...new Set(values)].sort((left, right) => left - right);
}

function uniqueSortedStrings(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}
