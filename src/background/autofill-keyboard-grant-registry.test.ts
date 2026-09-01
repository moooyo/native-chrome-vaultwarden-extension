import { describe, expect, it, vi } from 'vitest';
import {
  AutofillKeyboardGrantRegistry,
  type KeyboardGrantIssue,
} from './autofill-keyboard-grant-registry.js';
import {
  EMPTY_LOGIN_CUSTOM_PLAN,
  EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
} from '../core/vault/login-custom-fields.js';

interface SessionLease { generation: number }
interface AccountLease { serverGeneration: number; accountGeneration: number }
interface PolicyLease { generation: number }

const SESSION: SessionLease = Object.freeze({ generation: 1 });
const ACCOUNT: AccountLease = Object.freeze({ serverGeneration: 2, accountGeneration: 3 });
const POLICY: PolicyLease = Object.freeze({ generation: 4 });
const COMMAND = Object.freeze({
  tabId: 7,
  topDocumentId: 'top-doc',
  topFrameUrl: 'https://example.com/',
  sessionLease: SESSION,
});
const CONTEXT = Object.freeze({
  tabId: 7,
  frameId: 2,
  documentId: 'child-doc',
  frameUrl: 'https://example.com/login',
});

function uuid(sequence: number): string {
  return `00000000-0000-4000-8000-${String(sequence).padStart(12, '0')}`;
}

function harness(options: { commandTtlMs?: number; grantTtlMs?: number } = {}) {
  let now = 0;
  let tokenSequence = 0;
  let currentSession = SESSION;
  let currentAccount = ACCOUNT;
  let currentPolicy = POLICY;
  const registry = new AutofillKeyboardGrantRegistry<SessionLease, AccountLease, PolicyLease>({
    isSessionLeaseCurrent: (lease) => lease.generation === currentSession.generation,
    isAccountLeaseCurrent: (lease) => lease.serverGeneration === currentAccount.serverGeneration
      && lease.accountGeneration === currentAccount.accountGeneration,
    isPolicyLeaseCurrent: (lease) => lease.generation === currentPolicy.generation,
    now: () => now,
    createToken: () => uuid(++tokenSequence),
    ...options,
  });
  return {
    registry,
    setNow(value: number) { now = value; },
    setSession(value: SessionLease) { currentSession = value; },
    setAccount(value: AccountLease) { currentAccount = value; },
    setPolicy(value: PolicyLease) { currentPolicy = value; },
  };
}

function loginGrant(overrides: Partial<KeyboardGrantIssue<SessionLease, AccountLease, PolicyLease>> = {}) {
  return {
    ...CONTEXT,
    topDocumentId: COMMAND.topDocumentId,
    topFrameUrl: COMMAND.topFrameUrl,
    binding: {
      purpose: 'login' as const,
      customPlan: EMPTY_LOGIN_CUSTOM_PLAN,
      customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
    },
    sessionLease: SESSION,
    accountLease: ACCOUNT,
    policyLease: POLICY,
    ...overrides,
  };
}

describe('AutofillKeyboardGrantRegistry', () => {
  it('binds a browser command to one tab and top document and consumes it atomically', () => {
    const { registry } = harness();
    const token = registry.issueCommand(COMMAND);

    expect(registry.takeCommand(token, COMMAND)).toEqual(COMMAND);
    expect(registry.takeCommand(token, COMMAND)).toBeUndefined();

    const mismatched = registry.issueCommand(COMMAND);
    expect(registry.takeCommand(mismatched, { ...COMMAND, topDocumentId: 'new-top' })).toBeUndefined();
    expect(registry.takeCommand(mismatched, COMMAND)).toBeUndefined();
  });

  it('expires a command at its deadline', () => {
    const { registry, setNow } = harness({ commandTtlMs: 10 });
    const token = registry.issueCommand(COMMAND);
    setNow(10);
    expect(registry.takeCommand(token, COMMAND)).toBeUndefined();
  });

  it('rejects an old command across a lock or unlock generation and revokes all capability classes', () => {
    const { registry, setSession } = harness();
    const command = registry.issueCommand(COMMAND);
    const grant = registry.issueGrant(loginGrant());

    setSession({ generation: 2 });
    expect(registry.takeCommand(command, COMMAND)).toBeUndefined();
    registry.revokeAll();
    expect(registry.authorizeGrant(grant, CONTEXT)).toBeUndefined();
  });

  it('keeps an exact grant for candidate reads and consumes it for final intent issuance', () => {
    const { registry } = harness();
    const token = registry.issueGrant(loginGrant());

    expect(registry.authorizeGrant(token, CONTEXT)).toMatchObject({
      ...CONTEXT,
      purpose: 'login',
      topDocumentId: COMMAND.topDocumentId,
      sessionLease: SESSION,
      accountLease: ACCOUNT,
      policyLease: POLICY,
    });
    expect(registry.authorizeGrant(token, CONTEXT)).toBeDefined();
    expect(registry.consumeGrant(token, CONTEXT)).toBeDefined();
    expect(registry.authorizeGrant(token, CONTEXT)).toBeUndefined();
    expect(registry.consumeGrant(token, CONTEXT)).toBeUndefined();
  });

  it.each([
    ['tab', { tabId: 8 }],
    ['frame', { frameId: 3 }],
    ['document', { documentId: 'other-doc' }],
    ['URL', { frameUrl: 'https://example.com/other' }],
  ])('fails closed and consumes a grant on a mismatched %s', (_label, mismatch) => {
    const { registry } = harness();
    const token = registry.issueGrant(loginGrant());

    expect(registry.authorizeGrant(token, { ...CONTEXT, ...mismatch })).toBeUndefined();
    expect(registry.consumeGrant(token, CONTEXT)).toBeUndefined();
  });

  it.each(['session', 'account', 'policy'] as const)(
    'invalidates a grant when the %s lease changes and rejects replay',
    (kind) => {
      const state = harness();
      const token = state.registry.issueGrant(loginGrant());
      if (kind === 'session') state.setSession({ generation: 9 });
      else if (kind === 'account') state.setAccount({ serverGeneration: 2, accountGeneration: 9 });
      else state.setPolicy({ generation: 9 });

      expect(state.registry.authorizeGrant(token, CONTEXT)).toBeUndefined();
      expect(state.registry.consumeGrant(token, CONTEXT)).toBeUndefined();
    },
  );

  it('expires a grant and refuses to issue one with a stale lease', () => {
    const state = harness({ grantTtlMs: 10 });
    const token = state.registry.issueGrant(loginGrant());
    state.setNow(10);
    expect(state.registry.consumeGrant(token, CONTEXT)).toBeUndefined();

    state.setSession({ generation: 9 });
    expect(() => state.registry.issueGrant(loginGrant())).toThrow('stale');
  });

  it('canonicalizes a structured binding and rejects cross-kind or noncanonical roles', () => {
    const { registry } = harness();
    const binding = {
      purpose: 'card' as const,
      structuredTarget: {
        kind: 'card' as const,
        formId: 'form-1',
        generation: 5,
        roles: ['number', 'exp', 'code'] as const,
      },
    };
    const token = registry.issueGrant(loginGrant({ binding }));
    expect(registry.consumeGrant(token, CONTEXT)).toMatchObject({ purpose: 'card', binding });

    expect(() => registry.issueGrant(loginGrant({
      binding: {
        ...binding,
        structuredTarget: { ...binding.structuredTarget, roles: ['code', 'number'] },
      },
    }))).toThrow('binding');
    expect(() => registry.issueGrant(loginGrant({
      binding: {
        purpose: 'identity',
        structuredTarget: binding.structuredTarget,
      },
    }))).toThrow('binding');
  });

  it('treats lease-validator exceptions as a consumed failure', () => {
    const validator = vi.fn().mockReturnValueOnce(true).mockImplementation(() => {
      throw new Error('gate unavailable');
    });
    const registry = new AutofillKeyboardGrantRegistry<SessionLease, AccountLease, PolicyLease>({
      isSessionLeaseCurrent: validator,
      isAccountLeaseCurrent: () => true,
      isPolicyLeaseCurrent: () => true,
      createToken: () => uuid(1),
      now: () => 0,
    });
    const token = registry.issueGrant(loginGrant());

    expect(registry.authorizeGrant(token, CONTEXT)).toBeUndefined();
    expect(registry.consumeGrant(token, CONTEXT)).toBeUndefined();
  });
});
