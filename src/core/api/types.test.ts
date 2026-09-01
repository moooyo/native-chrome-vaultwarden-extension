import { describe, it, expect } from 'vitest';
import type {
  CipherBulkShareRequest,
  CipherRequest,
  CipherResponse,
  CipherWithIdRequest,
  CollectionAccessDetails,
  LoginSuccessResponse,
  PreloginResponse,
  SyncResponse,
} from './types.js';

describe('api types casing', () => {
  it('keeps prelogin camelCase and login PascalCase distinct', () => {
    const prelogin: PreloginResponse = { kdf: 0, kdfIterations: 600000 };
    const login: LoginSuccessResponse = {
      access_token: 'a',
      expires_in: 3600,
      refresh_token: 'r',
      token_type: 'Bearer',
      Key: '2.iv|ct|mac',
      Kdf: 0,
      KdfIterations: 600000,
    };
    expect(prelogin.kdfIterations).toBe(600000);
    expect(login.Key).toBe('2.iv|ct|mac');
  });

  it('models camelCase sync ciphers', () => {
    const cipher: CipherResponse = {
      id: 'cipher-1',
      type: 1,
      name: '2.n|c|m',
      favorite: false,
      organizationId: null,
      login: { username: '2.u|c|m', password: '2.p|c|m', uris: [{ uri: '2.uri|c|m' }] },
    };
    const sync: SyncResponse = { profile: { id: 'user-1', email: 'user@example.com' }, ciphers: [cipher] };
    expect(sync.ciphers[0]?.login?.uris?.[0]?.uri).toBe('2.uri|c|m');
  });

  it('preserves an unknown positive cipher type and its opaque encrypted payload', () => {
    const cipher: CipherResponse = {
      id: 'future-cipher',
      type: 6,
      name: '2.encrypted-name',
      bankAccount: {
        accountNumber: '2.encrypted-account-number',
        routingNumber: '2.encrypted-routing-number',
      },
    };
    const sync: SyncResponse = {
      profile: { id: 'user-1', email: 'user@example.com' },
      ciphers: [cipher],
    };

    expect(sync.ciphers[0]).toBe(cipher);
    expect(sync.ciphers[0]?.type).toBe(6);
    expect(sync.ciphers[0]?.bankAccount).toEqual(cipher.bankAccount);
  });

  it('models sparse SSH reads and requires a complete SSH write payload', () => {
    const response: CipherResponse = {
      id: 'ssh-read',
      type: 5,
      name: '2.encrypted-name',
      sshKey: { privateKey: '2.encrypted-private', publicKey: null },
    };
    const request: CipherRequest = {
      type: 5,
      name: '2.encrypted-name',
      sshKey: {
        privateKey: '2.encrypted-private',
        publicKey: '2.encrypted-public',
        keyFingerprint: '2.encrypted-fingerprint',
      },
    };

    expect(response.sshKey?.keyFingerprint).toBeUndefined();
    expect(request.sshKey?.keyFingerprint).toBe('2.encrypted-fingerprint');
  });

  it('models the official bulk-share envelope with ids on every encrypted cipher', () => {
    const cipher: CipherWithIdRequest = {
      id: 'cipher-1',
      encryptedFor: 'user-1',
      organizationId: 'org-1',
      type: 1,
      name: '2.encrypted-name',
      login: { username: '2.encrypted-username' },
    };
    const request: CipherBulkShareRequest = {
      ciphers: [cipher],
      collectionIds: ['collection-1'],
      encryptedFor: 'user-1',
    };

    expect(request.ciphers[0]?.id).toBe('cipher-1');
    expect(request.ciphers[0]?.encryptedFor).toBe(request.encryptedFor);
  });

  it('losslessly models policy, membership, and provider sync context', () => {
    const futurePolicyData = { restrictedItemTypes: [3], futureControl: { mode: 'strict' } };
    const organization = {
      id: 'org-1',
      key: '4.encrypted-org-key',
      status: 1,
      type: 2,
      enabled: true,
      usePolicies: true,
      usePasswordManager: true,
      organizationUserId: 'membership-1',
      limitCollectionCreation: false,
      futureEntitlement: 'retained',
    };
    const sync: SyncResponse = {
      profile: {
        id: 'user-1',
        email: 'user@example.com',
        premium: true,
        premiumFromOrganization: false,
        organizations: [],
        organizationsNew: [organization],
        providerOrganizations: [{ ...organization, id: 'provider-org' }],
        providers: [{ id: 'provider-1', futureProviderField: { retained: true } }],
        futureProfileField: ['retained'],
      },
      ciphers: [],
      policies: [],
      policiesNew: [{
        id: 'policy-future',
        organizationId: 'org-1',
        type: 99,
        enabled: true,
        data: futurePolicyData,
        futurePolicyField: 'retained',
      }],
      futureSyncField: { retained: true },
    };

    expect(sync.policiesNew?.[0]?.data).toBe(futurePolicyData);
    expect(sync.policiesNew?.[0]?.futurePolicyField).toBe('retained');
    expect(sync.profile.organizationsNew?.[0]?.futureEntitlement).toBe('retained');
    expect(sync.profile.organizationsNew?.[0]?.organizationUserId).toBe('membership-1');
    expect(sync.profile.premium).toBe(true);
    expect(sync.profile.providers?.[0]?.futureProviderField).toEqual({ retained: true });
    expect(sync.futureSyncField).toEqual({ retained: true });
  });

  it('models collection access flags used to authorize organization targets', () => {
    const sync: SyncResponse = {
      profile: { id: 'user-1', email: 'user@example.com' },
      ciphers: [],
      collections: [{
        id: 'collection-1',
        organizationId: 'org-1',
        name: '2.encrypted-name',
        readOnly: false,
        manage: true,
        hidePasswords: false,
        assigned: true,
        type: 0,
      }],
    };

    expect(sync.collections?.[0]).toMatchObject({
      readOnly: false,
      manage: true,
      hidePasswords: false,
      assigned: true,
      type: 0,
    });

    const details: CollectionAccessDetails = {
      id: 'collection-1',
      organizationId: 'org-1',
      groups: [{ id: 'group-1' }],
      users: [{ id: 'user-1' }],
      externalId: 'directory-collection-1',
    };
    expect(details.externalId).toBe('directory-collection-1');
  });
});
