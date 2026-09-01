import { describe, expect, it } from 'vitest';
import type { OrganizationResponse, SyncProfile } from '../api/types.js';
import {
  selectOrganizationKeySources,
  selectOrganizationMetadata,
} from './organization-profile.js';

function profile(overrides: Partial<SyncProfile> = {}): SyncProfile {
  return { id: 'user-1', email: 'user@example.com', ...overrides };
}

function organization(id: string, overrides: Partial<OrganizationResponse> = {}): OrganizationResponse {
  return { id, ...overrides };
}

describe('selectOrganizationMetadata', () => {
  it('treats a present empty organizationsNew collection as authoritative', () => {
    const selection = selectOrganizationMetadata(profile({
      organizations: [organization('legacy')],
      organizationsNew: [],
    }));

    expect(selection.source).toBe('organizationsNew');
    expect(selection.entries).toEqual([]);
  });

  it.each([
    ['absent', {}],
    ['null', { organizationsNew: null }],
  ] as const)('falls back to legacy organizations when organizationsNew is %s', (_label, override) => {
    const selection = selectOrganizationMetadata(profile({
      organizations: [organization('legacy')],
      ...override,
    }));

    expect(selection.source).toBe('organizations');
    expect(selection.entries).toEqual([{
      organization: expect.objectContaining({ id: 'legacy' }),
      isMember: true,
      isProviderUser: false,
    }]);
  });

  it('merges direct and provider visibility while retaining direct membership metadata', () => {
    const direct = organization('shared', { name: 'Direct membership' });
    const provider = organization('shared', { name: 'Provider projection', providerId: 'provider-1' });
    const providerOnly = organization('provider-only', { providerId: 'provider-1' });
    const selection = selectOrganizationMetadata(profile({
      organizationsNew: [direct],
      providerOrganizations: [provider, providerOnly],
    }));

    expect(selection.entries).toEqual([
      { organization: direct, isMember: true, isProviderUser: true },
      { organization: providerOnly, isMember: false, isProviderUser: true },
    ]);
  });

  it('drops malformed empty identifiers without changing source authority', () => {
    const selection = selectOrganizationMetadata(profile({
      organizationsNew: [organization(''), organization('valid')],
    }));

    expect(selection.source).toBe('organizationsNew');
    expect(selection.entries.map(({ organization: entry }) => entry.id)).toEqual(['valid']);
  });
});

describe('selectOrganizationKeySources', () => {
  it('keeps direct, provider, and provider-organization envelopes separate', () => {
    const direct = organization('direct', { key: '4.direct' });
    const accepted = organization('accepted', { key: '4.must-not-be-used', status: 1 });
    const provider = { id: 'provider-1', key: '4.provider' };
    const providerOrganization = organization('provider-org', {
      key: '2.provider-org',
      providerId: 'provider-1',
    });

    const sources = selectOrganizationKeySources(profile({
      organizations: [direct],
      organizationsNew: [accepted],
      providers: [provider],
      providerOrganizations: [providerOrganization],
    }));

    expect(sources.directOrganizations).toEqual([direct]);
    expect(sources.providers).toEqual([provider]);
    expect(sources.providerOrganizations).toEqual([providerOrganization]);
    expect(sources.directOrganizations).not.toContain(accepted);
  });

  it('normalizes absent or malformed wire collections to empty arrays', () => {
    const sources = selectOrganizationKeySources(profile({
      organizations: null,
      providerOrganizations: 'invalid' as never,
    }));

    expect(sources).toEqual({
      directOrganizations: [],
      providers: [],
      providerOrganizations: [],
    });
  });
});
