import { describe, expect, it, vi } from 'vitest';
import {
  VaultExportGrantRegistry,
  VaultExportGrantRegistryError,
  type VaultExportGrantEncryptionType,
} from './vault-export-grant-registry.js';

const TOKEN_A = '11111111-1111-4111-8111-111111111111';
const TOKEN_B = '22222222-2222-4222-8222-222222222222';
const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

function fixture(options: { ttlMs?: number; maxEntries?: number } = {}) {
  let now = 1_000;
  let tokenIndex = 0;
  const current = { session: 1, account: 1, policy: 1 };
  const registry = new VaultExportGrantRegistry<number, number, number>({
    isSessionLeaseCurrent: (lease) => lease === current.session,
    isAccountLeaseCurrent: (lease) => lease === current.account,
    isPolicyLeaseCurrent: (lease) => lease === current.policy,
    now: () => now,
    createToken: () => [TOKEN_A, TOKEN_B][tokenIndex++] ?? crypto.randomUUID(),
    ...options,
  });
  const issue = (
    format: 'json' | 'encrypted-json' | 'csv' | 'zip' = 'json',
    encryptionType: VaultExportGrantEncryptionType | undefined = format === 'encrypted-json'
      ? 'account'
      : undefined,
  ) => registry.issue({
    format,
    ...(encryptionType ? { encryptionType } : {}),
    sessionLease: current.session,
    accountLease: current.account,
    policyLease: current.policy,
  });
  return { registry, current, issue, setNow: (value: number) => { now = value; } };
}

describe('VaultExportGrantRegistry', () => {
  it('redeems an exact-format grant once with its bound leases', () => {
    const { registry, issue } = fixture();
    const receipt = issue('zip');

    expect(registry.redeem(receipt.authorizationId, 'zip')).toEqual({
      format: 'zip',
      target: { kind: 'personal' },
      sessionLease: 1,
      accountLease: 1,
      policyLease: 1,
    });
    expect(registry.redeem(receipt.authorizationId, 'zip')).toBeUndefined();
  });

  it('binds CSV grants to CSV and consumes them on any format mismatch', () => {
    const { registry, issue } = fixture();
    const receipt = issue('csv');

    expect(registry.redeem(receipt.authorizationId, 'csv')).toMatchObject({ format: 'csv' });
    expect(registry.redeem(receipt.authorizationId, 'csv')).toBeUndefined();

    const mismatched = issue('csv');
    expect(registry.redeem(mismatched.authorizationId, 'json')).toBeUndefined();
    expect(registry.redeem(mismatched.authorizationId, 'csv')).toBeUndefined();
  });

  it('consumes a grant before rejecting a format mismatch', () => {
    const { registry, issue } = fixture();
    const receipt = issue('encrypted-json');

    expect(registry.redeem(receipt.authorizationId, 'json')).toBeUndefined();
    expect(registry.redeem(receipt.authorizationId, 'encrypted-json')).toBeUndefined();
  });

  it('binds encrypted JSON grants to one exact encryption mode and consumes mismatches', () => {
    const { registry, issue } = fixture();
    const account = issue('encrypted-json', 'account');
    expect(registry.redeem(account.authorizationId, 'encrypted-json', 'file')).toBeUndefined();
    expect(registry.redeem(account.authorizationId, 'encrypted-json', 'account')).toBeUndefined();

    const file = issue('encrypted-json', 'file');
    expect(registry.redeem(file.authorizationId, 'encrypted-json', 'file')).toMatchObject({
      format: 'encrypted-json',
      encryptionType: 'file',
    });
  });

  it('binds organization grants to one exact target and consumes target mismatches', () => {
    const { registry, current } = fixture();
    const first = registry.issue({
      format: 'json',
      target: { kind: 'organization', organizationId: ORG_A.toUpperCase() },
      sessionLease: current.session,
      accountLease: current.account,
      policyLease: current.policy,
    });

    expect(registry.redeem(
      first.authorizationId,
      'json',
      undefined,
      { kind: 'organization', organizationId: ORG_B },
    )).toBeUndefined();
    expect(registry.redeem(
      first.authorizationId,
      'json',
      undefined,
      { kind: 'organization', organizationId: ORG_A },
    )).toBeUndefined();

    const second = registry.issue({
      format: 'encrypted-json',
      encryptionType: 'account',
      target: { kind: 'organization', organizationId: ORG_A },
      sessionLease: current.session,
      accountLease: current.account,
      policyLease: current.policy,
    });
    expect(registry.redeem(
      second.authorizationId,
      'encrypted-json',
      'account',
      { kind: 'organization', organizationId: ORG_A },
    )).toMatchObject({
      format: 'encrypted-json',
      encryptionType: 'account',
      target: { kind: 'organization', organizationId: ORG_A },
    });
  });

  it('rejects organization ZIP grants before issuing a capability', () => {
    const { registry, current } = fixture();
    expect(() => registry.issue({
      format: 'zip',
      target: { kind: 'organization', organizationId: ORG_A },
      sessionLease: current.session,
      accountLease: current.account,
      policyLease: current.policy,
    })).toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
  });

  it('rejects malformed or accessor-backed organization targets without evaluating accessors', () => {
    const { registry, current } = fixture();
    const getter = vi.fn(() => ORG_A);
    const accessorTarget = Object.defineProperty(
      { kind: 'organization' },
      'organizationId',
      { enumerable: true, get: getter },
    );
    const base = {
      format: 'json' as const,
      sessionLease: current.session,
      accountLease: current.account,
      policyLease: current.policy,
    };

    expect(() => registry.issue({ ...base, target: accessorTarget as never }))
      .toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
    expect(getter).not.toHaveBeenCalled();
    expect(() => registry.issue({
      ...base,
      target: { kind: 'organization', organizationId: 'not-a-uuid' },
    })).toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
    expect(() => registry.issue({
      ...base,
      target: { kind: 'personal', extra: true } as never,
    })).toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
  });

  it('consumes stale and expired grants without exposing why they failed', () => {
    const stale = fixture({ ttlMs: 10 });
    const staleReceipt = stale.issue();
    stale.current.session += 1;
    expect(stale.registry.redeem(staleReceipt.authorizationId, 'json')).toBeUndefined();

    const expired = fixture({ ttlMs: 10 });
    const expiredReceipt = expired.issue();
    expired.setNow(expiredReceipt.expiresAt);
    expect(expired.registry.redeem(expiredReceipt.authorizationId, 'json')).toBeUndefined();
  });

  it('prunes expired grants before enforcing capacity', () => {
    const { issue, setNow } = fixture({ ttlMs: 10, maxEntries: 1 });
    const first = issue();
    expect(() => issue()).toThrowError(expect.objectContaining({ code: 'capacity' }));

    setNow(first.expiresAt);
    expect(issue('zip').authorizationId).toBe(TOKEN_B);
  });

  it('rejects stale issue leases and invalid token generators', () => {
    const stale = fixture();
    stale.current.policy += 1;
    expect(() => stale.registry.issue({
      format: 'json', sessionLease: 1, accountLease: 1, policyLease: 1,
    })).toThrowError(expect.objectContaining({ code: 'invalid_grant' }));

    const invalid = new VaultExportGrantRegistry<number, number, number>({
      isSessionLeaseCurrent: () => true,
      isAccountLeaseCurrent: () => true,
      isPolicyLeaseCurrent: () => true,
      createToken: () => 'not-a-token',
    });
    expect(() => invalid.issue({
      format: 'json', sessionLease: 1, accountLease: 1, policyLease: 1,
    })).toThrowError(VaultExportGrantRegistryError);
  });

  it('revokes every outstanding grant without an inspection API', () => {
    const { registry, issue } = fixture();
    const first = issue('json');
    const second = issue('zip');
    registry.revokeAll();

    expect(registry.redeem(first.authorizationId, 'json')).toBeUndefined();
    expect(registry.redeem(second.authorizationId, 'zip')).toBeUndefined();
  });
});
