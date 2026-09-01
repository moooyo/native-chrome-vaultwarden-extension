import { describe, expect, it } from 'vitest';
import {
  MAX_REPROMPT_AUTOFILL_GRANT_CAPACITY,
  MAX_REPROMPT_AUTOFILL_GRANT_TTL_MS,
  RepromptAutofillGrantRegistry,
  type RepromptAutofillGrantBinding,
} from './reprompt-autofill-grant-registry.js';

const TOKEN_A = '11111111-1111-4111-8111-111111111111';
const TOKEN_B = '22222222-2222-4222-8222-222222222222';

const BINDING: RepromptAutofillGrantBinding = Object.freeze({
  popupDocumentId: 'popup-doc-1',
  cipherId: 'cipher-1',
  tabId: 7,
  frameId: 2,
  targetDocumentId: 'target-doc-1',
  topUrl: 'https://example.com/login',
  frameUrl: 'https://accounts.example.com/frame?step=2',
  targetKey: 'login|form-1|4|digest',
});

function harness(options: { ttlMs?: number; maxEntries?: number; tokens?: string[] } = {}) {
  let now = 1_000;
  let tokenIndex = 0;
  const current = { session: 1, account: 1, policy: 1 };
  const tokens = options.tokens ?? [TOKEN_A, TOKEN_B];
  const registry = new RepromptAutofillGrantRegistry<number, number, number>({
    isSessionLeaseCurrent: (lease) => lease === current.session,
    isAccountLeaseCurrent: (lease) => lease === current.account,
    isPolicyLeaseCurrent: (lease) => lease === current.policy,
    now: () => now,
    createToken: () => tokens[tokenIndex++] ?? crypto.randomUUID(),
    ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
    ...(options.maxEntries === undefined ? {} : { maxEntries: options.maxEntries }),
  });
  const issue = (binding: RepromptAutofillGrantBinding = BINDING) => registry.issue({
    ...binding,
    sessionLease: current.session,
    accountLease: current.account,
    policyLease: current.policy,
  });
  return { registry, current, issue, setNow: (value: number) => { now = value; } };
}

describe('RepromptAutofillGrantRegistry', () => {
  it('redeems an exact browser and Popup binding once with the original leases', () => {
    const { registry, issue } = harness();
    const receipt = issue({
      ...BINDING,
      topUrl: 'HTTPS://EXAMPLE.COM:443/account/../login',
    });

    const redeemed = registry.redeem(receipt.authorizationId, BINDING);
    expect(redeemed).toMatchObject({
      sessionLease: 1,
      accountLease: 1,
      policyLease: 1,
      expiresAt: receipt.expiresAt,
    });
    expect(redeemed?.isCurrent()).toBe(true);
    expect(registry.redeem(receipt.authorizationId, BINDING)).toBeUndefined();
  });

  it.each([
    ['Popup document', { popupDocumentId: 'popup-doc-old' }],
    ['cipher', { cipherId: 'cipher-old' }],
    ['tab', { tabId: 8 }],
    ['frame', { frameId: 3 }],
    ['target document', { targetDocumentId: 'target-doc-old' }],
    ['top URL', { topUrl: 'https://example.com/other' }],
    ['frame URL', { frameUrl: 'https://accounts.example.com/other' }],
    ['target snapshot', { targetKey: 'login|form-1|5|digest' }],
  ])('consumes a grant before rejecting a mismatched %s', (_label, change) => {
    const { registry, issue } = harness();
    const receipt = issue();
    expect(registry.redeem(receipt.authorizationId, { ...BINDING, ...change })).toBeUndefined();
    expect(registry.redeem(receipt.authorizationId, BINDING)).toBeUndefined();
  });

  it.each(['session', 'account', 'policy'] as const)('consumes a stale %s grant', (kind) => {
    const { registry, issue, current } = harness();
    const receipt = issue();
    current[kind] += 1;
    expect(registry.redeem(receipt.authorizationId, BINDING)).toBeUndefined();
    expect(registry.redeem(receipt.authorizationId, BINDING)).toBeUndefined();
  });

  it('expires at the deadline and reclaims bounded capacity', () => {
    const { registry, issue, setNow } = harness({ ttlMs: 10, maxEntries: 1 });
    const expired = issue();
    expect(() => issue()).toThrowError(expect.objectContaining({ code: 'capacity' }));
    setNow(expired.expiresAt);
    const replacement = issue({ ...BINDING, cipherId: 'cipher-2' });
    expect(replacement.authorizationId).toBe(TOKEN_B);
    expect(registry.redeem(replacement.authorizationId, { ...BINDING, cipherId: 'cipher-2' }))
      .toMatchObject({ sessionLease: 1 });
  });

  it('rejects stale issue leases without consuming capacity', () => {
    const { registry, issue, current } = harness({ maxEntries: 1 });
    current.policy += 1;
    expect(() => registry.issue({
      ...BINDING,
      sessionLease: 1,
      accountLease: 1,
      policyLease: 1,
    })).toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
    current.policy -= 1;
    expect(issue().authorizationId).toBe(TOKEN_A);
  });

  it('revokes every outstanding grant without an inspection API', () => {
    const { registry, issue } = harness();
    const first = issue();
    const second = issue({ ...BINDING, cipherId: 'cipher-2' });
    registry.revokeAll();
    expect(registry.redeem(first.authorizationId, BINDING)).toBeUndefined();
    expect(registry.redeem(second.authorizationId, { ...BINDING, cipherId: 'cipher-2' })).toBeUndefined();
    expect(Object.keys(registry)).toEqual([]);
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(registry)).sort())
      .toEqual(['constructor', 'issue', 'redeem', 'revokeAll']);
  });

  it('keeps a redeemed grant bound to its deadline and revocation epoch', () => {
    const { registry, issue, setNow } = harness({ ttlMs: 10 });
    const expires = issue();
    const expiredAfterRedeem = registry.redeem(expires.authorizationId, BINDING);
    expect(expiredAfterRedeem?.isCurrent()).toBe(true);
    setNow(expires.expiresAt);
    expect(expiredAfterRedeem?.isCurrent()).toBe(false);

    setNow(2_000);
    const revoked = issue({ ...BINDING, cipherId: 'cipher-2' });
    const revokedAfterRedeem = registry.redeem(
      revoked.authorizationId,
      { ...BINDING, cipherId: 'cipher-2' },
    );
    expect(revokedAfterRedeem?.isCurrent()).toBe(true);
    registry.revokeAll();
    expect(revokedAfterRedeem?.isCurrent()).toBe(false);
  });

  it('rejects malformed inputs, token generators, and configured bounds', () => {
    const { registry } = harness();
    expect(() => registry.issue({
      ...BINDING,
      frameUrl: 'file:///tmp/login',
      sessionLease: 1,
      accountLease: 1,
      policyLease: 1,
    })).toThrowError(expect.objectContaining({ code: 'invalid_grant' }));

    const invalidToken = new RepromptAutofillGrantRegistry<number, number, number>({
      isSessionLeaseCurrent: () => true,
      isAccountLeaseCurrent: () => true,
      isPolicyLeaseCurrent: () => true,
      createToken: () => 'predictable',
    });
    expect(() => invalidToken.issue({
      ...BINDING,
      sessionLease: 1,
      accountLease: 1,
      policyLease: 1,
    })).toThrowError(expect.objectContaining({ code: 'token_generation' }));

    for (const options of [
      { ttlMs: 0 },
      { ttlMs: MAX_REPROMPT_AUTOFILL_GRANT_TTL_MS + 1 },
      { maxEntries: 0 },
      { maxEntries: MAX_REPROMPT_AUTOFILL_GRANT_CAPACITY + 1 },
    ]) {
      expect(() => new RepromptAutofillGrantRegistry<number, number, number>({
        isSessionLeaseCurrent: () => true,
        isAccountLeaseCurrent: () => true,
        isPolicyLeaseCurrent: () => true,
        ...options,
      })).toThrowError(expect.objectContaining({ code: 'invalid_configuration' }));
    }
  });
});
