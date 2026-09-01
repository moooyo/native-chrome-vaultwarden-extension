import type {
  OrganizationResponse,
  ProviderOrganizationResponse,
  ProviderResponse,
  SyncProfile,
} from '../api/types.js';

export type OrganizationMetadataSource = 'organizationsNew' | 'organizations' | 'none';

export interface OrganizationMetadataEntry {
  readonly organization: OrganizationResponse;
  readonly isMember: boolean;
  readonly isProviderUser: boolean;
}

export interface OrganizationMetadataSelection {
  readonly source: OrganizationMetadataSource;
  readonly entries: readonly OrganizationMetadataEntry[];
}

export interface OrganizationKeySources {
  /** Confirmed direct memberships whose keys are encapsulated to the account public key. */
  readonly directOrganizations: readonly OrganizationResponse[];
  /** Provider keys encapsulated to the account public key. */
  readonly providers: readonly ProviderResponse[];
  /** Organization keys wrapped by the matching provider key. */
  readonly providerOrganizations: readonly ProviderOrganizationResponse[];
}

/**
 * Select the authoritative organization metadata collection and merge provider visibility.
 * `organizationsNew` is authoritative whenever present, including an empty array; unlike the
 * legacy collection, it may contain both accepted and confirmed direct memberships.
 */
export function selectOrganizationMetadata(profile: SyncProfile): OrganizationMetadataSelection {
  const hasOrganizationsNew = profile.organizationsNew !== null
    && profile.organizationsNew !== undefined;
  const directOrganizations = hasOrganizationsNew
    ? arrayOrEmpty(profile.organizationsNew)
    : arrayOrEmpty(profile.organizations);
  const source: OrganizationMetadataSource = hasOrganizationsNew
    ? 'organizationsNew'
    : Array.isArray(profile.organizations) ? 'organizations' : 'none';
  const entries = new Map<string, OrganizationMetadataEntry>();

  for (const organization of directOrganizations) {
    if (!hasOrganizationId(organization)) continue;
    entries.set(organization.id, Object.freeze({
      organization,
      isMember: true,
      isProviderUser: false,
    }));
  }

  for (const organization of arrayOrEmpty(profile.providerOrganizations)) {
    if (!hasOrganizationId(organization)) continue;
    const direct = entries.get(organization.id);
    entries.set(organization.id, direct
      ? Object.freeze({ ...direct, isProviderUser: true })
      : Object.freeze({
          organization,
          isMember: false,
          isProviderUser: true,
        }));
  }

  return Object.freeze({ source, entries: Object.freeze([...entries.values()]) });
}

/**
 * Return the three independent key-envelope collections from sync. `organizationsNew` is
 * intentionally absent: accepted memberships are metadata, not authority to derive an org key.
 */
export function selectOrganizationKeySources(profile: SyncProfile): OrganizationKeySources {
  return Object.freeze({
    directOrganizations: Object.freeze([...arrayOrEmpty(profile.organizations)]),
    providers: Object.freeze([...arrayOrEmpty(profile.providers)]),
    providerOrganizations: Object.freeze([...arrayOrEmpty(profile.providerOrganizations)]),
  });
}

function arrayOrEmpty<T>(value: readonly T[] | null | undefined): readonly T[] {
  return Array.isArray(value) ? value : [];
}

function hasOrganizationId(
  organization: OrganizationResponse,
): organization is OrganizationResponse & { id: string } {
  return typeof organization?.id === 'string' && organization.id.trim().length > 0;
}
