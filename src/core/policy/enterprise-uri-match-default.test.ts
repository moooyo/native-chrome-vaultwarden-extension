import { describe, expect, it } from 'vitest';

import type { EffectiveEnterprisePolicySnapshot } from './effective-enterprise-policy.js';
import { resolveEnterpriseUriMatchDefault } from './enterprise-uri-match-default.js';
import { UriMatchStrategy, type UriMatchStrategySetting } from '../vault/uri-match.js';

type UriMatchDefaultsSnapshot = Pick<
  EffectiveEnterprisePolicySnapshot,
  'uriMatchDefaultsPolicy'
>;

function snapshot(
  policy: EffectiveEnterprisePolicySnapshot['uriMatchDefaultsPolicy'],
): UriMatchDefaultsSnapshot {
  return { uriMatchDefaultsPolicy: policy };
}

describe('resolveEnterpriseUriMatchDefault', () => {
  it('preserves the local default when no enterprise policy applies', () => {
    expect(resolveEnterpriseUriMatchDefault(UriMatchStrategy.Exact, snapshot(null))).toEqual({
      value: UriMatchStrategy.Exact,
      managed: false,
      malformed: false,
    });
  });

  it('treats the numeric Domain value as a managed policy value instead of falling back', () => {
    expect(resolveEnterpriseUriMatchDefault(UriMatchStrategy.Never, snapshot({
      organizationId: 'organization-id',
      malformed: false,
      value: UriMatchStrategy.Domain,
    }))).toEqual({
      value: UriMatchStrategy.Domain,
      managed: true,
      malformed: false,
    });
  });

  it('uses every valid nonzero managed strategy exactly', () => {
    for (const value of [
      UriMatchStrategy.Host,
      UriMatchStrategy.StartsWith,
      UriMatchStrategy.Exact,
      UriMatchStrategy.RegularExpression,
      UriMatchStrategy.Never,
    ] as const) {
      expect(resolveEnterpriseUriMatchDefault(UriMatchStrategy.Domain, snapshot({
        organizationId: null,
        malformed: false,
        value,
      }))).toEqual({ value, managed: true, malformed: false });
    }
  });

  it('fails a policy marked malformed closed to Never', () => {
    expect(resolveEnterpriseUriMatchDefault(UriMatchStrategy.Domain, snapshot({
      organizationId: 'organization-id',
      malformed: true,
      value: UriMatchStrategy.Host,
    }))).toEqual({
      value: UriMatchStrategy.Never,
      managed: true,
      malformed: true,
    });
  });

  it.each([
    undefined,
    { organizationId: null, malformed: false, value: 6 },
    { organizationId: 42, malformed: false, value: UriMatchStrategy.Host },
    { organizationId: null, malformed: 'false', value: UriMatchStrategy.Host },
  ])('fails a forged policy shape closed to Never: %j', (policy) => {
    expect(resolveEnterpriseUriMatchDefault(
      UriMatchStrategy.Exact,
      snapshot(policy as never),
    )).toEqual({
      value: UriMatchStrategy.Never,
      managed: true,
      malformed: true,
    });
  });

  it('fails an invalid local setting closed without claiming organization management', () => {
    expect(resolveEnterpriseUriMatchDefault(
      6 as UriMatchStrategySetting,
      snapshot(null),
    )).toEqual({
      value: UriMatchStrategy.Never,
      managed: false,
      malformed: true,
    });
  });
});
