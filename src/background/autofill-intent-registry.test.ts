import { describe, expect, it, vi } from 'vitest';
import {
  AutofillIntentRegistry,
  DEFAULT_AUTOFILL_INTENT_CAPACITY,
  DEFAULT_AUTOFILL_INTENT_TTL_MS,
  MAX_AUTOFILL_INTENT_CAPACITY,
  MAX_AUTOFILL_INTENT_TTL_MS,
  type AutofillIntentIssue,
  type AutofillIntentRedemption,
} from './autofill-intent-registry.js';
import {
  EMPTY_LOGIN_CUSTOM_PLAN,
  EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
} from '../core/vault/login-custom-fields.js';

interface SessionLease {
  readonly generation: number;
}

interface AccountLease {
  readonly serverGeneration: number;
  readonly accountGeneration: number;
  readonly accountIdentity: string;
}

interface PolicyLease {
  readonly generation: number;
}

const SESSION: SessionLease = Object.freeze({ generation: 7 });
const ACCOUNT: AccountLease = Object.freeze({
  serverGeneration: 2,
  accountGeneration: 5,
  accountIdentity: 'user@example.com',
});
const POLICY: PolicyLease = Object.freeze({ generation: 9 });
const RUNTIME_INCARNATION = 'a0b1c2d3-e4f5-4a6b-8c9d-0123456789ab';
const OTHER_RUNTIME_INCARNATION = 'b0c1d2e3-f4a5-4b6c-9d8e-1234567890ab';

const ISSUE: AutofillIntentIssue<SessionLease, AccountLease, PolicyLease> = {
  tabId: 11,
  frameId: 3,
  documentId: 'doc-abc',
  runtimeIncarnation: RUNTIME_INCARNATION,
  frameUrl: 'https://example.com/login?step=2',
  cipherId: 'cipher-123',
  purpose: 'login',
  channel: 'interactive',
  sessionLease: SESSION,
  accountLease: ACCOUNT,
  policyLease: POLICY,
  customPlan: EMPTY_LOGIN_CUSTOM_PLAN,
  customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
};

const REDEMPTION: AutofillIntentRedemption = {
  tabId: ISSUE.tabId,
  frameId: ISSUE.frameId,
  documentId: ISSUE.documentId,
  runtimeIncarnation: ISSUE.runtimeIncarnation,
  frameUrl: ISSUE.frameUrl,
  purpose: ISSUE.purpose,
  channel: ISSUE.channel,
};

function uuid(sequence: number): string {
  return `00000000-0000-4000-8000-${String(sequence).padStart(12, '0')}`;
}

function makeHarness(options: { ttlMs?: number; maxEntries?: number; tokens?: string[] } = {}) {
  let now = 0;
  let nextToken = 0;
  let currentSession = SESSION;
  let currentAccount = ACCOUNT;
  let currentPolicy = POLICY;
  const tokens = options.tokens ?? Array.from({ length: 32 }, (_, index) => uuid(index + 1));
  const isSessionLeaseCurrent = vi.fn((issued: SessionLease) => (
    issued.generation === currentSession.generation
  ));
  const isAccountLeaseCurrent = vi.fn((issued: AccountLease) => (
    issued.serverGeneration === currentAccount.serverGeneration
    && issued.accountGeneration === currentAccount.accountGeneration
    && issued.accountIdentity === currentAccount.accountIdentity
  ));
  const isPolicyLeaseCurrent = vi.fn((issued: PolicyLease) => issued.generation === currentPolicy.generation);
  const registry = new AutofillIntentRegistry<SessionLease, AccountLease, PolicyLease>({
    isSessionLeaseCurrent,
    isAccountLeaseCurrent,
    isPolicyLeaseCurrent,
    ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
    ...(options.maxEntries === undefined ? {} : { maxEntries: options.maxEntries }),
    now: () => now,
    createToken: () => tokens[nextToken++] ?? uuid(nextToken + 1000),
  });
  return {
    registry,
    isSessionLeaseCurrent,
    isAccountLeaseCurrent,
    isPolicyLeaseCurrent,
    setNow(value: number) { now = value; },
    setCurrentSession(value: SessionLease) { currentSession = value; },
    setCurrentAccount(value: AccountLease) { currentAccount = value; },
    setCurrentPolicy(value: PolicyLease) { currentPolicy = value; },
  };
}

function issue(overrides: Partial<AutofillIntentIssue<SessionLease, AccountLease, PolicyLease>> = {}) {
  const result: AutofillIntentIssue<SessionLease, AccountLease, PolicyLease> = { ...ISSUE, ...overrides };
  if (result.purpose !== 'login' || result.channel === 'page-load') {
    delete (result as { customPlan?: unknown }).customPlan;
    delete (result as { customPlanDigest?: unknown }).customPlanDigest;
  }
  return result;
}

function redemption(overrides: Partial<AutofillIntentRedemption> = {}) {
  return { ...REDEMPTION, ...overrides };
}

describe('AutofillIntentRegistry', () => {
  it('keeps the browser-keyboard channel distinct from ordinary interactive redemption', () => {
    const { registry } = makeHarness();
    const token = registry.issue(issue({ channel: 'keyboard' }));

    expect(registry.redeem(token, redemption({ channel: 'interactive' }))).toBeUndefined();
    expect(registry.redeem(token, redemption({ channel: 'keyboard' }))).toBeUndefined();

    const valid = registry.issue(issue({ channel: 'keyboard' }));
    expect(registry.redeem(valid, redemption({ channel: 'keyboard' }))).toMatchObject({
      purpose: 'login', channel: 'keyboard', customPlan: EMPTY_LOGIN_CUSTOM_PLAN,
    });
  });

  it('keeps a verified reprompt assertion internal to one keyboard intent redemption', () => {
    const { registry } = makeHarness();
    const assertCurrent = vi.fn();
    const authorization = Object.freeze({ assertCurrent });
    const token = registry.issue(issue({ channel: 'keyboard', repromptAuthorization: authorization }));

    const redeemed = registry.redeem(token, redemption({ channel: 'keyboard' }));
    expect(redeemed?.repromptAuthorization).toBeDefined();
    redeemed?.repromptAuthorization?.assertCurrent();
    expect(assertCurrent).toHaveBeenCalledOnce();
    expect(registry.redeem(token, redemption({ channel: 'keyboard' }))).toBeUndefined();
    expect(() => registry.issue(issue({ channel: 'interactive', repromptAuthorization: authorization })))
      .toThrowError(expect.objectContaining({ code: 'invalid_intent' }));
  });

  it.each(['login', 'totp'] as const)('issues an opaque UUID and redeems the %s cipher exactly once', (purpose) => {
    const { registry } = makeHarness();
    const token = registry.issue(issue({
      purpose,
      frameUrl: 'HTTPS://EXAMPLE.COM:443/account/../login?step=2#form',
    }));

    expect(token).toMatch(/^[0-9a-f-]{36}$/i);
    expect(registry.redeem(token, redemption({
      purpose,
      frameUrl: 'https://example.com/login?step=2#form',
    }))).toEqual({
      tabId: ISSUE.tabId,
      frameId: ISSUE.frameId,
      documentId: ISSUE.documentId,
      runtimeIncarnation: ISSUE.runtimeIncarnation,
      canonicalFrameUrl: 'https://example.com/login?step=2#form',
      cipherId: ISSUE.cipherId,
      purpose,
      channel: 'interactive',
      sessionLease: SESSION,
      accountLease: ACCOUNT,
      policyLease: POLICY,
      ...(purpose === 'login' ? { customPlan: EMPTY_LOGIN_CUSTOM_PLAN, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST } : {}),
    });
    expect(registry.redeem(token, redemption({ purpose }))).toBeUndefined();
  });

  it('binds a structured intent to the exact form generation and canonical role projection', () => {
    const { registry } = makeHarness();
    const structuredTarget = Object.freeze({
      kind: 'card' as const,
      runtimeIncarnation: RUNTIME_INCARNATION,
      formId: 'frame-form-7',
      generation: 12,
      roles: ['number', 'exp', 'code'] as const,
    });
    const token = registry.issue(issue({ purpose: 'card', structuredTarget }));

    expect(registry.redeem(token, redemption({ purpose: 'card', structuredTarget }))).toEqual({
      tabId: ISSUE.tabId,
      frameId: ISSUE.frameId,
      documentId: ISSUE.documentId,
      runtimeIncarnation: ISSUE.runtimeIncarnation,
      canonicalFrameUrl: ISSUE.frameUrl,
      cipherId: ISSUE.cipherId,
      purpose: 'card',
      channel: 'interactive',
      sessionLease: SESSION,
      accountLease: ACCOUNT,
      policyLease: POLICY,
      structuredTarget,
    });
  });

  it.each([
    ['form id', { formId: 'other-form' }],
    ['generation', { generation: 13 }],
    ['roles', { roles: ['number'] as const }],
    ['runtime incarnation', { runtimeIncarnation: OTHER_RUNTIME_INCARNATION }],
  ])('consumes a structured intent on a mismatched %s', (_label, change) => {
    const { registry } = makeHarness();
    const structuredTarget = {
      kind: 'card' as const,
      runtimeIncarnation: RUNTIME_INCARNATION,
      formId: 'frame-form-7',
      generation: 12,
      roles: ['number', 'exp', 'code'] as const,
    };
    const token = registry.issue(issue({ purpose: 'card', structuredTarget }));
    const mismatched = { ...structuredTarget, ...change };

    expect(registry.redeem(token, redemption({ purpose: 'card', structuredTarget: mismatched }))).toBeUndefined();
    expect(registry.redeem(token, redemption({ purpose: 'card', structuredTarget }))).toBeUndefined();
  });

  it('rejects missing, cross-kind, and noncanonical structured bindings', () => {
    const { registry } = makeHarness();
    expect(() => registry.issue(issue({ purpose: 'card' }))).toThrowError(
      expect.objectContaining({ code: 'invalid_intent' }),
    );
    expect(() => registry.issue(issue({
      purpose: 'identity',
      structuredTarget: {
        kind: 'card',
        runtimeIncarnation: RUNTIME_INCARNATION,
        formId: 'form',
        generation: 1,
        roles: ['number'],
      },
    }))).toThrowError(expect.objectContaining({ code: 'invalid_intent' }));
    expect(() => registry.issue(issue({
      purpose: 'card',
      structuredTarget: {
        kind: 'card',
        runtimeIncarnation: RUNTIME_INCARNATION,
        formId: 'form',
        generation: 1,
        roles: ['code', 'number'],
      },
    }))).toThrowError(expect.objectContaining({ code: 'invalid_intent' }));
    expect(() => registry.issue(issue({
      purpose: 'card',
      structuredTarget: {
        kind: 'card',
        runtimeIncarnation: OTHER_RUNTIME_INCARNATION,
        formId: 'form',
        generation: 1,
        roles: ['number'],
      },
    }))).toThrowError(expect.objectContaining({ code: 'invalid_intent' }));
  });

  it('does not consume an intent when a different opaque token is tried', () => {
    const { registry } = makeHarness();
    const token = registry.issue(ISSUE);

    expect(registry.redeem(uuid(999), REDEMPTION)).toBeUndefined();
    expect(registry.redeem(token, REDEMPTION)).toEqual({
      tabId: ISSUE.tabId,
      frameId: ISSUE.frameId,
      documentId: ISSUE.documentId,
      runtimeIncarnation: ISSUE.runtimeIncarnation,
      canonicalFrameUrl: ISSUE.frameUrl,
      cipherId: ISSUE.cipherId,
      purpose: 'login',
      channel: 'interactive',
      sessionLease: SESSION,
      accountLease: ACCOUNT,
      policyLease: POLICY,
      customPlan: EMPTY_LOGIN_CUSTOM_PLAN,
      customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
    });
  });

  it.each([
    ['tab', { tabId: 12 }],
    ['frame', { frameId: 4 }],
    ['document', { documentId: 'doc-other' }],
    ['runtime incarnation', { runtimeIncarnation: OTHER_RUNTIME_INCARNATION }],
    ['URL', { frameUrl: 'https://example.com/other' }],
    ['URL fragment', { frameUrl: 'https://example.com/login?step=2#other-route' }],
    ['purpose', { purpose: 'totp' as const }],
    ['channel', { channel: 'page-load' as const }],
  ])('fails closed and consumes the token on a mismatched %s', (_label, mismatch) => {
    const { registry } = makeHarness();
    const token = registry.issue(ISSUE);

    expect(registry.redeem(token, redemption(mismatch))).toBeUndefined();
    expect(registry.redeem(token, REDEMPTION)).toBeUndefined();
  });

  it('consumes an intent when redemption supplies a noncanonical runtime incarnation', () => {
    const { registry } = makeHarness();
    const token = registry.issue(ISSUE);

    expect(registry.redeem(token, redemption({
      runtimeIncarnation: RUNTIME_INCARNATION.toUpperCase(),
    }))).toBeUndefined();
    expect(registry.redeem(token, REDEMPTION)).toBeUndefined();
  });

  it('validates both stored leases even when browser context is wrong', () => {
    const { registry, isSessionLeaseCurrent, isAccountLeaseCurrent } = makeHarness();
    const token = registry.issue(ISSUE);
    isSessionLeaseCurrent.mockClear();
    isAccountLeaseCurrent.mockClear();

    expect(registry.redeem(token, redemption({ documentId: 'wrong-document' }))).toBeUndefined();
    expect(isSessionLeaseCurrent).toHaveBeenCalledOnce();
    expect(isAccountLeaseCurrent).toHaveBeenCalledOnce();
  });

  it.each(['session', 'account', 'policy'] as const)('consumes the token when the %s lease becomes stale', (kind) => {
    const harness = makeHarness();
    const token = harness.registry.issue(ISSUE);
    if (kind === 'session') harness.setCurrentSession({ generation: SESSION.generation + 1 });
    else if (kind === 'account') harness.setCurrentAccount({ ...ACCOUNT, accountGeneration: ACCOUNT.accountGeneration + 1 });
    else harness.setCurrentPolicy({ generation: POLICY.generation + 1 });

    expect(harness.registry.redeem(token, REDEMPTION)).toBeUndefined();
    expect(harness.registry.redeem(token, REDEMPTION)).toBeUndefined();
  });

  it('refuses to issue with a stale lease before consuming token capacity', () => {
    const harness = makeHarness({ maxEntries: 1 });
    harness.setCurrentSession({ generation: SESSION.generation + 1 });
    expect(() => harness.registry.issue(ISSUE)).toThrowError(
      expect.objectContaining({ code: 'invalid_intent' }),
    );

    harness.setCurrentSession(SESSION);
    const token = harness.registry.issue(ISSUE);
    expect(harness.registry.redeem(token, REDEMPTION)).toMatchObject({ cipherId: ISSUE.cipherId });
  });

  it('treats lease-validator exceptions as an indistinguishable consumed failure', () => {
    const isSessionLeaseCurrent = vi.fn()
      .mockReturnValueOnce(true)
      .mockImplementation(() => { throw new Error('gate unavailable'); });
    const registry = new AutofillIntentRegistry<SessionLease, AccountLease, PolicyLease>({
      isSessionLeaseCurrent,
      isAccountLeaseCurrent: () => true,
      isPolicyLeaseCurrent: () => true,
      now: () => 0,
      createToken: () => uuid(1),
    });
    const token = registry.issue(ISSUE);

    expect(registry.redeem(token, REDEMPTION)).toBeUndefined();
    expect(registry.redeem(token, REDEMPTION)).toBeUndefined();
  });

  it('expires at the deadline and lazily reclaims capacity', () => {
    const { registry, setNow } = makeHarness({ ttlMs: 100, maxEntries: 1 });
    const expired = registry.issue(ISSUE);
    setNow(100);

    expect(registry.redeem(expired, REDEMPTION)).toBeUndefined();
    const replacement = registry.issue(issue({ cipherId: 'cipher-new' }));
    expect(registry.redeem(replacement, REDEMPTION)).toEqual({
      tabId: ISSUE.tabId,
      frameId: ISSUE.frameId,
      documentId: ISSUE.documentId,
      runtimeIncarnation: ISSUE.runtimeIncarnation,
      canonicalFrameUrl: ISSUE.frameUrl,
      cipherId: 'cipher-new',
      purpose: 'login',
      channel: 'interactive',
      sessionLease: SESSION,
      accountLease: ACCOUNT,
      policyLease: POLICY,
      customPlan: EMPTY_LOGIN_CUSTOM_PLAN,
      customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
    });
  });

  it('rejects at capacity without evicting a live intent', () => {
    const { registry } = makeHarness({ maxEntries: 1 });
    const first = registry.issue(ISSUE);

    expect(() => registry.issue(issue({ cipherId: 'cipher-second' }))).toThrowError(
      expect.objectContaining({ code: 'capacity' }),
    );
    expect(registry.redeem(first, REDEMPTION)).toMatchObject({ cipherId: ISSUE.cipherId, purpose: 'login' });
  });

  it('fails closed on token collision without replacing the original intent', () => {
    const repeated = uuid(1);
    const { registry } = makeHarness({ maxEntries: 2, tokens: Array.from({ length: 5 }, () => repeated) });
    const first = registry.issue(ISSUE);

    expect(() => registry.issue(issue({ cipherId: 'cipher-second' }))).toThrowError(
      expect.objectContaining({ code: 'token_collision' }),
    );
    expect(registry.redeem(first, REDEMPTION)).toMatchObject({ cipherId: ISSUE.cipherId, purpose: 'login' });
  });

  it('retries a UUID collision with a fresh token', () => {
    const firstToken = uuid(1);
    const secondToken = uuid(2);
    const { registry } = makeHarness({ maxEntries: 2, tokens: [firstToken, firstToken, secondToken] });
    expect(registry.issue(ISSUE)).toBe(firstToken);
    expect(registry.issue(issue({ cipherId: 'cipher-second' }))).toBe(secondToken);
  });

  it('consumes the token before rejecting an invalid redemption URL', () => {
    const { registry } = makeHarness();
    const token = registry.issue(ISSUE);

    expect(registry.redeem(token, redemption({ frameUrl: 'not a URL' }))).toBeUndefined();
    expect(registry.redeem(token, REDEMPTION)).toBeUndefined();
  });

  it.each([
    ['non-HTTP URL', { frameUrl: 'file:///tmp/login.html' }],
    ['credentialed URL', { frameUrl: 'https://user:pass@example.com/login' }],
    ['empty document', { documentId: '' }],
    ['uppercase runtime incarnation', { runtimeIncarnation: RUNTIME_INCARNATION.toUpperCase() }],
    ['non-v4 runtime incarnation', { runtimeIncarnation: 'a0b1c2d3-e4f5-5a6b-8c9d-0123456789ab' }],
    ['negative tab', { tabId: -1 }],
    ['invalid purpose', { purpose: 'card' as 'login' }],
    ['invalid channel', { channel: 'background' as 'interactive' }],
    ['missing session lease', { sessionLease: undefined as unknown as SessionLease }],
  ])('rejects an invalid issued intent: %s', (_label, invalid) => {
    const { registry } = makeHarness();
    expect(() => registry.issue(issue(invalid))).toThrowError(
      expect.objectContaining({ code: 'invalid_intent' }),
    );
  });

  it.each([
    [{ ttlMs: 0 }, 'ttlMs'],
    [{ ttlMs: MAX_AUTOFILL_INTENT_TTL_MS + 1 }, 'ttlMs'],
    [{ maxEntries: 0 }, 'maxEntries'],
    [{ maxEntries: MAX_AUTOFILL_INTENT_CAPACITY + 1 }, 'maxEntries'],
  ])('rejects invalid bounds %j', (bounds, _label) => {
    expect(() => new AutofillIntentRegistry<SessionLease, AccountLease, PolicyLease>({
      isSessionLeaseCurrent: () => true,
      isAccountLeaseCurrent: () => true,
      isPolicyLeaseCurrent: () => true,
      ...bounds,
    })).toThrowError(expect.objectContaining({ code: 'invalid_configuration' }));
  });

  it('rejects a non-UUID token generator', () => {
    const registry = new AutofillIntentRegistry<SessionLease, AccountLease, PolicyLease>({
      isSessionLeaseCurrent: () => true,
      isAccountLeaseCurrent: () => true,
      isPolicyLeaseCurrent: () => true,
      now: () => 0,
      createToken: () => 'predictable-token',
    });

    expect(() => registry.issue(ISSUE)).toThrowError(expect.objectContaining({ code: 'token_generation' }));
  });

  it('exposes no capability enumeration surface', () => {
    const { registry } = makeHarness();

    expect(Object.keys(registry)).toEqual([]);
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(registry)).sort())
      .toEqual(['constructor', 'issue', 'redeem']);
  });

  it('exports conservative default bounds', () => {
    expect(DEFAULT_AUTOFILL_INTENT_TTL_MS).toBeLessThanOrEqual(MAX_AUTOFILL_INTENT_TTL_MS);
    expect(DEFAULT_AUTOFILL_INTENT_CAPACITY).toBeLessThanOrEqual(MAX_AUTOFILL_INTENT_CAPACITY);
  });
});
