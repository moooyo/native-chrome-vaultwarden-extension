import { describe, expect, it, vi } from 'vitest';
import { EMPTY_LOGIN_CUSTOM_PLAN_DIGEST } from '../core/vault/login-custom-fields.js';
import {
  DEFAULT_MANUAL_AUTOFILL_GRANT_CAPACITY,
  DEFAULT_MANUAL_AUTOFILL_GRANT_TTL_MS,
  MAX_MANUAL_AUTOFILL_GRANT_CAPACITY,
  MAX_MANUAL_AUTOFILL_GRANT_TTL_MS,
  ManualAutofillGrantRegistry,
  type ManualAutofillGrantBinding,
  type ManualAutofillGrantCallerContext,
  type ManualAutofillGrantIssue,
} from './manual-autofill-grant-registry.js';

interface Lease { readonly generation: number }

const TOKEN_A = '11111111-1111-4111-8111-111111111111';
const TOKEN_B = '22222222-2222-4222-8222-222222222222';
const TOKEN_C = '33333333-3333-4333-8333-333333333333';
const SESSION = Object.freeze({ generation: 1 });
const ACCOUNT = Object.freeze({ generation: 2 });
const AUTOFILL_POLICY = Object.freeze({ generation: 3 });
const ENTERPRISE_POLICY = Object.freeze({ generation: 4 });
const VAULT_AUTHORITY = Object.freeze({ generation: 5 });

const BINDING: ManualAutofillGrantBinding = Object.freeze({
  popupDocumentId: 'popup-document-1',
  cipherId: 'cipher-1',
  tabId: 7,
  topUrl: 'https://example.com/login',
  frameUrl: 'https://accounts.example.com/frame?step=2',
  frameId: 3,
  targetDocumentId: 'target-document-1',
  formId: 'login-form-1',
  generation: 9,
  customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
  cipherRevision: '2026-08-31T10:20:30.000Z',
  uriDigest: '1'.repeat(64),
  risk: 'no_match',
  requiresReprompt: false,
});
const CALLER = Object.freeze({ popupDocumentId: BINDING.popupDocumentId });

const ISSUE: ManualAutofillGrantIssue<Lease, Lease, Lease, Lease, Lease> = Object.freeze({
  ...BINDING,
  allowedActions: Object.freeze(['fill_only', 'fill_and_save'] as const),
  sessionLease: SESSION,
  accountLease: ACCOUNT,
  autofillPolicyLease: AUTOFILL_POLICY,
  enterprisePolicyLease: ENTERPRISE_POLICY,
  vaultAuthority: VAULT_AUTHORITY,
});

function harness(options: {
  ttlMs?: number;
  maxEntries?: number;
  tokens?: string[];
} = {}) {
  let now = 1_000;
  let tokenIndex = 0;
  const current = { session: 1, account: 2, autofill: 3, enterprise: 4, vault: 5 };
  const tokens = options.tokens ?? [TOKEN_A, TOKEN_B, TOKEN_C];
  const validators = {
    session: vi.fn((value: Lease) => value.generation === current.session),
    account: vi.fn((value: Lease) => value.generation === current.account),
    autofill: vi.fn((value: Lease) => value.generation === current.autofill),
    enterprise: vi.fn((value: Lease) => value.generation === current.enterprise),
    vault: vi.fn((value: Lease) => value.generation === current.vault),
  };
  const registry = new ManualAutofillGrantRegistry<Lease, Lease, Lease, Lease, Lease>({
    isSessionLeaseCurrent: validators.session,
    isAccountLeaseCurrent: validators.account,
    isAutofillPolicyLeaseCurrent: validators.autofill,
    isEnterprisePolicyLeaseCurrent: validators.enterprise,
    isVaultAuthorityCurrent: validators.vault,
    now: () => now,
    createToken: () => tokens[tokenIndex++] ?? crypto.randomUUID(),
    ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
    ...(options.maxEntries === undefined ? {} : { maxEntries: options.maxEntries }),
  });
  return {
    registry,
    current,
    validators,
    setNow(value: number) { now = value; },
  };
}

function issue(
  overrides: Partial<ManualAutofillGrantIssue<Lease, Lease, Lease, Lease, Lease>> = {},
): ManualAutofillGrantIssue<Lease, Lease, Lease, Lease, Lease> {
  return { ...ISSUE, ...overrides };
}

describe('ManualAutofillGrantRegistry', () => {
  it('returns a minimal Popup receipt and redeems an exact grant once', () => {
    const { registry } = harness();
    const receipt = registry.issue(issue({
      topUrl: 'HTTPS://EXAMPLE.COM:443/account/../login',
      frameUrl: 'HTTPS://ACCOUNTS.EXAMPLE.COM:443/frame?step=2',
    }));

    expect(receipt).toEqual({ grantId: TOKEN_A, expiresAt: 31_000 });
    expect(JSON.parse(JSON.stringify(receipt))).toEqual(receipt);
    expect(Object.keys(receipt).sort()).toEqual(['expiresAt', 'grantId']);
    const proof = registry.redeem(receipt.grantId, CALLER, 'fill_only');
    expect(proof?.action).toBe('fill_only');
    expect(proof?.sessionLease).toBe(SESSION);
    expect(proof?.accountLease).toBe(ACCOUNT);
    expect(proof?.autofillPolicyLease).toBe(AUTOFILL_POLICY);
    expect(proof?.enterprisePolicyLease).toBe(ENTERPRISE_POLICY);
    expect(proof?.vaultAuthority).toBe(VAULT_AUTHORITY);
    expect(proof?.binding).toEqual(BINDING);
    expect(Object.isFrozen(proof?.binding)).toBe(true);
    expect(proof?.isCurrent()).toBe(true);
    expect(() => proof?.assertCurrent()).not.toThrow();
    expect(JSON.parse(JSON.stringify(proof))).toEqual({ action: 'fill_only', expiresAt: 31_000 });
    expect(registry.redeem(receipt.grantId, CALLER, 'fill_only')).toBeUndefined();
  });

  it('authorizes fill-and-save only when the issuer included that exact action', () => {
    const allowed = harness();
    const allowedReceipt = allowed.registry.issue(ISSUE);
    expect(allowed.registry.redeem(allowedReceipt.grantId, CALLER, 'fill_and_save')?.action)
      .toBe('fill_and_save');

    const fillOnly = harness();
    const deniedReceipt = fillOnly.registry.issue(issue({ allowedActions: ['fill_only'] }));
    expect(fillOnly.registry.redeem(deniedReceipt.grantId, CALLER, 'fill_and_save')).toBeUndefined();
    expect(fillOnly.registry.redeem(deniedReceipt.grantId, CALLER, 'fill_only')).toBeUndefined();
  });

  it.each(['never', 'https_downgrade'] as const)(
    'never grants fill-and-save for %s risk',
    (risk) => {
      const { registry } = harness();
      expect(() => registry.issue(issue({ risk })))
        .toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
      expect(registry.issue(issue({ risk, allowedActions: ['fill_only'] })).grantId).toBe(TOKEN_A);
    },
  );

  it('consumes before rejecting a caller from the wrong Popup document', () => {
    const { registry } = harness();
    const receipt = registry.issue(ISSUE);
    expect(registry.redeem(receipt.grantId, { popupDocumentId: 'other-popup' }, 'fill_only'))
      .toBeUndefined();
    expect(registry.redeem(receipt.grantId, CALLER, 'fill_only')).toBeUndefined();
  });

  it.each([
    ['tab', { tabId: 8 }],
    ['frame', { frameId: 4 }],
    ['form', { formId: 'forged-form' }],
  ])('rejects and consumes a caller context that tries to inject %s metadata', (_label, extra) => {
    const { registry } = harness();
    const receipt = registry.issue(ISSUE);
    expect(registry.redeem(receipt.grantId, { ...CALLER, ...extra }, 'fill_only'))
      .toBeUndefined();
    expect(registry.redeem(receipt.grantId, CALLER, 'fill_only')).toBeUndefined();
  });

  it('consumes both exact and mismatched cancellations', () => {
    const exact = harness();
    const exactReceipt = exact.registry.issue(ISSUE);
    expect(exact.registry.cancel(exactReceipt.grantId, CALLER)).toBe(true);
    expect(exact.registry.redeem(exactReceipt.grantId, CALLER, 'fill_only')).toBeUndefined();

    const mismatch = harness();
    const mismatchReceipt = mismatch.registry.issue(ISSUE);
    expect(mismatch.registry.cancel(
      mismatchReceipt.grantId,
      { popupDocumentId: 'closed-popup' },
    )).toBe(false);
    expect(mismatch.registry.redeem(mismatchReceipt.grantId, CALLER, 'fill_only')).toBeUndefined();
  });

  it.each(['session', 'account', 'autofill', 'enterprise', 'vault'] as const)(
    'consumes a grant when the %s authority changes',
    (kind) => {
      const state = harness();
      const receipt = state.registry.issue(ISSUE);
      state.current[kind] += 1;
      expect(state.registry.redeem(receipt.grantId, CALLER, 'fill_only')).toBeUndefined();
      expect(state.registry.redeem(receipt.grantId, CALLER, 'fill_only')).toBeUndefined();
    },
  );

  it('runs every authority callback and treats callback exceptions as a consumed denial', () => {
    const state = harness();
    const receipt = state.registry.issue(ISSUE);
    for (const validator of Object.values(state.validators)) validator.mockClear();
    state.validators.session.mockImplementation(() => { throw new Error('gate unavailable'); });

    expect(state.registry.redeem(receipt.grantId, CALLER, 'fill_only')).toBeUndefined();
    expect(state.validators.session).toHaveBeenCalledOnce();
    expect(state.validators.account).toHaveBeenCalledOnce();
    expect(state.validators.autofill).toHaveBeenCalledOnce();
    expect(state.validators.enterprise).toHaveBeenCalledOnce();
    expect(state.validators.vault).toHaveBeenCalledOnce();
    expect(state.registry.redeem(receipt.grantId, CALLER, 'fill_only')).toBeUndefined();
  });

  it('keeps a redeemed proof fenced by its deadline, leases, and synchronous revocation epoch', () => {
    const expired = harness({ ttlMs: 10 });
    const expires = expired.registry.issue(ISSUE);
    const expirationProof = expired.registry.redeem(expires.grantId, CALLER, 'fill_only');
    expired.setNow(expires.expiresAt);
    expect(expirationProof?.isCurrent()).toBe(false);
    expect(() => expirationProof?.assertCurrent()).toThrowError(
      expect.objectContaining({ code: 'invalid_grant' }),
    );

    const stale = harness();
    const staleReceipt = stale.registry.issue(ISSUE);
    const staleProof = stale.registry.redeem(staleReceipt.grantId, CALLER, 'fill_only');
    stale.current.enterprise += 1;
    expect(staleProof?.isCurrent()).toBe(false);
    expect(() => staleProof?.assertCurrent()).toThrowError(
      expect.objectContaining({ code: 'invalid_grant' }),
    );

    const revoked = harness();
    const proofReceipt = revoked.registry.issue(ISSUE);
    const proof = revoked.registry.redeem(proofReceipt.grantId, CALLER, 'fill_only');
    const outstanding = revoked.registry.issue(issue({ cipherId: 'cipher-2' }));
    revoked.registry.revokeAll();
    expect(proof?.isCurrent()).toBe(false);
    expect(() => proof?.assertCurrent()).toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
    expect(revoked.registry.redeem(
      outstanding.grantId,
      CALLER,
      'fill_only',
    )).toBeUndefined();
  });

  it('expires at the deadline and lazily reclaims bounded capacity', () => {
    const state = harness({ ttlMs: 10, maxEntries: 1 });
    const expired = state.registry.issue(ISSUE);
    expect(() => state.registry.issue(issue({ cipherId: 'cipher-2' })))
      .toThrowError(expect.objectContaining({ code: 'capacity' }));
    state.setNow(expired.expiresAt);
    const replacement = state.registry.issue(issue({ cipherId: 'cipher-2' }));
    expect(replacement.grantId).toBe(TOKEN_B);
    expect(state.registry.redeem(
      replacement.grantId,
      CALLER,
      'fill_only',
    )).toBeDefined();
  });

  it('never reuses a retired grant id and retries with a fresh UUID', () => {
    const state = harness({ tokens: [TOKEN_A, TOKEN_A, TOKEN_B, TOKEN_A, TOKEN_A, TOKEN_A, TOKEN_A] });
    const first = state.registry.issue(ISSUE);
    expect(state.registry.cancel(first.grantId, CALLER)).toBe(true);
    expect(state.registry.issue(issue({ cipherId: 'cipher-2' })).grantId).toBe(TOKEN_B);
    state.registry.revokeAll();
    expect(() => state.registry.issue(issue({ cipherId: 'cipher-3' })))
      .toThrowError(expect.objectContaining({ code: 'token_collision' }));
  });

  it('expires bounded ABA tombstones instead of retaining worker-lifetime token history', () => {
    const state = harness({ ttlMs: 10, tokens: [TOKEN_A, TOKEN_A] });
    const first = state.registry.issue(ISSUE);
    expect(state.registry.cancel(first.grantId, CALLER)).toBe(true);
    state.setNow(first.expiresAt);
    expect(state.registry.issue(issue({ cipherId: 'cipher-2' })).grantId).toBe(TOKEN_A);
  });

  it('rejects stale issue leases without consuming live capacity', () => {
    const state = harness({ maxEntries: 1 });
    state.current.autofill += 1;
    expect(() => state.registry.issue(ISSUE))
      .toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
    state.current.autofill -= 1;
    expect(state.registry.issue(ISSUE).grantId).toBe(TOKEN_A);
  });

  it.each([
    [{ ttlMs: 0 }, 'ttlMs'],
    [{ ttlMs: MAX_MANUAL_AUTOFILL_GRANT_TTL_MS + 1 }, 'ttlMs'],
    [{ maxEntries: 0 }, 'maxEntries'],
    [{ maxEntries: MAX_MANUAL_AUTOFILL_GRANT_CAPACITY + 1 }, 'maxEntries'],
  ])('rejects invalid registry bounds: %j', (bounds, _field) => {
    expect(() => new ManualAutofillGrantRegistry<Lease, Lease, Lease, Lease, Lease>({
      isSessionLeaseCurrent: () => true,
      isAccountLeaseCurrent: () => true,
      isAutofillPolicyLeaseCurrent: () => true,
      isEnterprisePolicyLeaseCurrent: () => true,
      isVaultAuthorityCurrent: () => true,
      ...bounds,
    })).toThrowError(expect.objectContaining({ code: 'invalid_configuration' }));
  });

  it('exports conservative defaults and exposes no inspection surface', () => {
    const { registry } = harness();
    expect(DEFAULT_MANUAL_AUTOFILL_GRANT_TTL_MS).toBe(30_000);
    expect(DEFAULT_MANUAL_AUTOFILL_GRANT_TTL_MS).toBeLessThanOrEqual(MAX_MANUAL_AUTOFILL_GRANT_TTL_MS);
    expect(DEFAULT_MANUAL_AUTOFILL_GRANT_CAPACITY)
      .toBeLessThanOrEqual(MAX_MANUAL_AUTOFILL_GRANT_CAPACITY);
    expect(Object.keys(registry)).toEqual([]);
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(registry)).sort())
      .toEqual(['cancel', 'constructor', 'issue', 'redeem', 'revokeAll']);
  });

  it.each([
    ['non-HTTP top URL', { topUrl: 'file:///tmp/login' }],
    ['credentialed frame URL', { frameUrl: 'https://user:pass@example.com/login' }],
    ['empty Popup document', { popupDocumentId: '' }],
    ['negative zero tab', { tabId: -0 }],
    ['negative frame', { frameId: -1 }],
    ['fractional generation', { generation: 1.5 }],
    ['invalid custom plan digest', { customPlanDigest: 'ABC' }],
    ['invalid URI digest', { uriDigest: 'A'.repeat(64) }],
    ['invalid revision', { cipherRevision: ' revision ' }],
    ['invalid risk', { risk: 'unknown' }],
    ['invalid reprompt flag', { requiresReprompt: 1 }],
    ['missing lease', { sessionLease: undefined }],
  ])('rejects invalid issue metadata: %s', (_label, invalid) => {
    const { registry } = harness();
    expect(() => registry.issue(issue(invalid as Partial<typeof ISSUE>)))
      .toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
  });

  it.each([
    ['missing fill-only', ['fill_and_save']],
    ['reversed actions', ['fill_and_save', 'fill_only']],
    ['duplicate action', ['fill_only', 'fill_only']],
    ['extra action', ['fill_only', 'fill_and_save', 'fill_only']],
  ])('rejects a noncanonical action capability: %s', (_label, allowedActions) => {
    const { registry } = harness();
    expect(() => registry.issue(issue({
      allowedActions: allowedActions as unknown as typeof ISSUE.allowedActions,
    }))).toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
  });

  it('rejects extra secret fields, symbols, and accessors without reading them', () => {
    const { registry } = harness();
    expect(() => registry.issue({ ...ISSUE, password: 'plaintext-must-not-enter-registry' } as
      typeof ISSUE & { password: string }))
      .toThrowError(expect.objectContaining({ code: 'invalid_grant' }));

    let getterCalled = false;
    const accessor = { ...ISSUE } as Record<PropertyKey, unknown>;
    Object.defineProperty(accessor, 'password', {
      enumerable: true,
      get() {
        getterCalled = true;
        return 'plaintext-must-not-enter-registry';
      },
    });
    expect(() => registry.issue(accessor as unknown as typeof ISSUE))
      .toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
    expect(getterCalled).toBe(false);

    const requiredAccessor = { ...ISSUE } as Record<PropertyKey, unknown>;
    Object.defineProperty(requiredAccessor, 'cipherId', {
      enumerable: true,
      get() {
        getterCalled = true;
        return 'cipher-1';
      },
    });
    expect(() => registry.issue(requiredAccessor as unknown as typeof ISSUE))
      .toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
    expect(getterCalled).toBe(false);

    const symbol = { ...ISSUE } as Record<PropertyKey, unknown>;
    symbol[Symbol('secret')] = 'plaintext-must-not-enter-registry';
    expect(() => registry.issue(symbol as unknown as typeof ISSUE))
      .toThrowError(expect.objectContaining({ code: 'invalid_grant' }));
  });

  it('consumes before rejecting a malformed claim object or selected action', () => {
    const malformed = harness();
    const malformedReceipt = malformed.registry.issue(ISSUE);
    expect(malformed.registry.redeem(
      malformedReceipt.grantId,
      { ...CALLER, password: 'plaintext' } as ManualAutofillGrantCallerContext,
      'fill_only',
    )).toBeUndefined();
    expect(malformed.registry.redeem(malformedReceipt.grantId, CALLER, 'fill_only')).toBeUndefined();

    const invalidAction = harness();
    const invalidActionReceipt = invalidAction.registry.issue(ISSUE);
    expect(invalidAction.registry.redeem(
      invalidActionReceipt.grantId,
      CALLER,
      'copy_password' as 'fill_only',
    )).toBeUndefined();
    expect(invalidAction.registry.redeem(invalidActionReceipt.grantId, CALLER, 'fill_only'))
      .toBeUndefined();

    const missingAction = harness();
    const missingActionReceipt = missingAction.registry.issue(ISSUE);
    expect(missingAction.registry.redeem(
      missingActionReceipt.grantId,
      CALLER,
      undefined as unknown as 'fill_only',
    )).toBeUndefined();
    expect(missingAction.registry.redeem(missingActionReceipt.grantId, CALLER, 'fill_only'))
      .toBeUndefined();
  });

  it('rejects a non-UUID or throwing token generator', () => {
    const base = {
      isSessionLeaseCurrent: () => true,
      isAccountLeaseCurrent: () => true,
      isAutofillPolicyLeaseCurrent: () => true,
      isEnterprisePolicyLeaseCurrent: () => true,
      now: () => 0,
    };
    const invalid = new ManualAutofillGrantRegistry<Lease, Lease, Lease, Lease, Lease>({
      ...base,
      isVaultAuthorityCurrent: () => true,
      createToken: () => 'predictable',
    });
    expect(() => invalid.issue(ISSUE))
      .toThrowError(expect.objectContaining({ code: 'token_generation' }));

    const throwing = new ManualAutofillGrantRegistry<Lease, Lease, Lease, Lease, Lease>({
      ...base,
      isVaultAuthorityCurrent: () => true,
      createToken: () => { throw new Error('rng unavailable'); },
    });
    expect(() => throwing.issue(ISSUE))
      .toThrowError(expect.objectContaining({ code: 'token_generation' }));
  });
});
