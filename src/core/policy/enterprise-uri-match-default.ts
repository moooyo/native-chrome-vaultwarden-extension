import type { EffectiveEnterprisePolicySnapshot } from './effective-enterprise-policy.js';
import {
  isUriMatchStrategySetting,
  UriMatchStrategy,
  type UriMatchStrategySetting,
} from '../vault/uri-match.js';

export interface EffectiveEnterpriseUriMatchDefault {
  readonly value: UriMatchStrategySetting;
  readonly managed: boolean;
  readonly malformed: boolean;
}

type UriMatchDefaultsSnapshot = Pick<
  EffectiveEnterprisePolicySnapshot,
  'uriMatchDefaultsPolicy'
>;

/** Resolve one validated local default against the policy snapshot that authorized the operation. */
export function resolveEnterpriseUriMatchDefault(
  userValue: UriMatchStrategySetting,
  snapshot: UriMatchDefaultsSnapshot,
): EffectiveEnterpriseUriMatchDefault {
  const policy = snapshot.uriMatchDefaultsPolicy;
  if (!isUriMatchStrategySetting(userValue)) {
    return failClosed(policy !== null);
  }
  if (policy === null) {
    return Object.freeze({ value: userValue, managed: false, malformed: false });
  }
  if (!isValidPolicy(policy) || policy.malformed) return failClosed(true);

  const policyValue = policy.value;
  return Object.freeze({
    value: policyValue ?? userValue,
    managed: true,
    malformed: false,
  });
}

function failClosed(managed: boolean): EffectiveEnterpriseUriMatchDefault {
  return Object.freeze({
    value: UriMatchStrategy.Never,
    managed,
    malformed: true,
  });
}

function isValidPolicy(
  policy: EffectiveEnterprisePolicySnapshot['uriMatchDefaultsPolicy'],
): policy is NonNullable<EffectiveEnterprisePolicySnapshot['uriMatchDefaultsPolicy']> {
  return policy !== null
    && typeof policy === 'object'
    && (typeof policy.organizationId === 'string' || policy.organizationId === null)
    && typeof policy.malformed === 'boolean'
    && isUriMatchStrategySetting(policy.value);
}
