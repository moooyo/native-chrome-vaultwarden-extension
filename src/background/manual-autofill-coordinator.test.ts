import { describe, expect, it, vi } from 'vitest';
import { AppError } from '../core/errors.js';
import type { AccountLease } from '../core/session/account-gate.js';
import type { SessionLease } from '../core/session/session-manager.js';
import type { PolicyLease } from '../core/policy/effective-enterprise-policy.js';
import type { ManualAutofillVaultAuthority } from '../core/vault/vault-service.js';
import { EMPTY_LOGIN_CUSTOM_PLAN, EMPTY_LOGIN_CUSTOM_PLAN_DIGEST } from '../core/vault/login-custom-fields.js';
import type { AutofillAuthorizationPolicyLease } from './autofill-authorization-policy.js';
import { ManualAutofillGrantRegistry } from './manual-autofill-grant-registry.js';
import { RepromptAutofillGrantRegistry } from './reprompt-autofill-grant-registry.js';
import { createManualAutofillCoordinator } from './manual-autofill-coordinator.js';
import type { ResolvedManualAutofillTarget } from './tab-autofill.js';

const POPUP_DOCUMENT = 'popup-document';
const MANUAL_TOKEN = '11111111-1111-4111-8111-111111111111';
const REPROMPT_TOKEN = '22222222-2222-4222-8222-222222222222';
const REVISION = '2026-09-01T00:00:00.0000001Z';
const URI_DIGEST = 'a'.repeat(64);

const SESSION: SessionLease = Object.freeze({ generation: 1 });
const ACCOUNT: AccountLease = Object.freeze({
  serverUrl: 'https://vault.example',
  accountIdentity: 'user@example.com',
  serverGeneration: 1,
  accountGeneration: 1,
});
const ENTERPRISE = Object.freeze({ generation: 1 }) as unknown as PolicyLease;
const POLICY = Object.freeze({
  autofill: Object.freeze({ generation: 1 }),
  enterprise: ENTERPRISE,
}) as unknown as AutofillAuthorizationPolicyLease;

const TARGET: ResolvedManualAutofillTarget = Object.freeze({
  tabId: 7,
  frameId: 0,
  targetDocumentId: 'target-document',
  topUrl: 'https://example.com/account/login?step=2',
  frameUrl: 'https://example.com/account/login?step=2',
  targetKey: JSON.stringify(['login', 0, 'form-1', 'target-document', 4, EMPTY_LOGIN_CUSTOM_PLAN_DIGEST]),
  target: Object.freeze({
    kind: 'login',
    frameId: 0,
    formId: 'form-1',
    documentId: 'target-document',
    generation: 4,
    customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
  }),
  customPlan: EMPTY_LOGIN_CUSTOM_PLAN,
  defaultStrategy: 0,
});

function harness(options: {
  canSave?: boolean;
  requiresReprompt?: boolean;
  risk?: 'no_match' | 'never' | 'https_downgrade';
} = {}) {
  let now = 1_000;
  let manualTokenUsed = false;
  const authorityCurrent = { value: true };
  const authority: ManualAutofillVaultAuthority = {
    assertCurrent: vi.fn(() => {
      if (!authorityCurrent.value) throw new AppError('conflict', 'stale vault');
    }),
  };
  const grants = new ManualAutofillGrantRegistry<
    SessionLease,
    AccountLease,
    AutofillAuthorizationPolicyLease,
    PolicyLease,
    ManualAutofillVaultAuthority
  >({
    isSessionLeaseCurrent: (lease) => lease === SESSION,
    isAccountLeaseCurrent: (lease) => lease === ACCOUNT,
    isAutofillPolicyLeaseCurrent: (lease) => lease === POLICY,
    isEnterprisePolicyLeaseCurrent: (lease) => lease === ENTERPRISE,
    isVaultAuthorityCurrent: (value) => {
      try { value.assertCurrent(); return true; } catch { return false; }
    },
    now: () => now,
    createToken: () => {
      if (manualTokenUsed) return crypto.randomUUID();
      manualTokenUsed = true;
      return MANUAL_TOKEN;
    },
  });
  const repromptGrants = new RepromptAutofillGrantRegistry<
    SessionLease,
    AccountLease,
    AutofillAuthorizationPolicyLease
  >({
    isSessionLeaseCurrent: (lease) => lease === SESSION,
    isAccountLeaseCurrent: (lease) => lease === ACCOUNT,
    isPolicyLeaseCurrent: (lease) => lease === POLICY,
    now: () => now,
    createToken: () => REPROMPT_TOKEN,
  });
  const resolveManualLoginTarget = vi.fn(async () => TARGET);
  const fillManual = vi.fn(async () => ({ status: 'filled' as const }));
  const prepareManualAutofill = vi.fn(async () => ({
    cipherRevision: REVISION,
    uriDigest: URI_DIGEST,
    risk: options.risk ?? 'no_match',
    requiresReprompt: options.requiresReprompt ?? false,
    canSave: options.canSave ?? true,
    authority,
  }));
  const saveManualAutofillUri = vi.fn(async () => ({
    items: [], folders: [], collections: [], orgPermissions: [],
  }));
  const authorizeSave = vi.fn(async () => ({ assertCurrent: vi.fn() }));
  const verifyMasterPassword = vi.fn(async (password: string) => password === 'correct-master');
  const coordinator = createManualAutofillCoordinator({
    grants,
    repromptGrants,
    tabAutofill: { resolveManualLoginTarget, fillManual },
    vault: { prepareManualAutofill, saveManualAutofillUri },
    sessionGate: { capture: () => SESSION, assert: (lease) => {
      if (lease !== SESSION) throw new AppError('locked', 'stale session');
    } },
    accountGate: { capture: () => ACCOUNT, assert: (lease) => {
      if (lease !== ACCOUNT) throw new AppError('session_expired', 'stale account');
    } },
    capturePolicy: () => POLICY,
    assertPolicy: (lease) => {
      if (lease !== POLICY) throw new AppError('denied', 'stale policy');
    },
    authorizeSave,
    verifyMasterPassword,
  });
  return {
    coordinator,
    grants,
    resolveManualLoginTarget,
    fillManual,
    prepareManualAutofill,
    saveManualAutofillUri,
    authorizeSave,
    verifyMasterPassword,
    authorityCurrent,
    setNow(value: number) { now = value; },
  };
}

async function prepare(state: ReturnType<typeof harness>) {
  return state.coordinator.prepare(POPUP_DOCUMENT, {
    type: 'autofill.manual.prepare',
    tabId: 7,
    cipherId: 'cipher-1',
  });
}

describe('manual autofill coordinator', () => {
  it('returns only warning projection and an opaque authorization for one stable target', async () => {
    const state = harness();
    const result = await prepare(state);

    expect(result).toEqual({
      warning: {
        risk: 'no_match',
        site: 'example.com',
        canSave: true,
        requiresReprompt: false,
      },
      authorization: { authorizationId: MANUAL_TOKEN, expiresAt: 31_000 },
    });
    expect(JSON.stringify(result)).not.toContain('target-document');
    expect(JSON.stringify(result)).not.toContain(REVISION);
    expect(state.resolveManualLoginTarget).toHaveBeenCalledTimes(2);
    expect(state.authorizeSave).toHaveBeenCalledWith(TARGET.topUrl, POLICY);
  });

  it('projects the browser-authoritative recipient for a cross-origin frame', async () => {
    const state = harness({ canSave: false });
    state.resolveManualLoginTarget.mockResolvedValue({
      ...TARGET,
      frameUrl: 'https://accounts.other.example/login',
    });
    await expect(prepare(state)).resolves.toMatchObject({
      warning: {
        site: 'example.com',
        recipientSite: 'accounts.other.example',
        canSave: false,
      },
    });
  });

  it('fails closed when discovery is ambiguous or changes during prepare', async () => {
    const unavailable = harness();
    unavailable.resolveManualLoginTarget.mockResolvedValue(undefined as never);
    await expect(prepare(unavailable)).rejects.toMatchObject({ code: 'denied' });

    const changed = harness();
    changed.resolveManualLoginTarget
      .mockResolvedValueOnce(TARGET)
      .mockResolvedValueOnce({ ...TARGET, targetDocumentId: 'other-document' });
    await expect(prepare(changed)).rejects.toMatchObject({ code: 'conflict' });
  });

  it('fills once, consumes before caller validation, and never saves', async () => {
    const state = harness();
    const prepared = await prepare(state);
    await expect(state.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: prepared.authorization.authorizationId,
      action: 'fill_only',
    })).resolves.toEqual({ status: 'filled' });
    expect(state.fillManual).toHaveBeenCalledOnce();
    expect(state.saveManualAutofillUri).not.toHaveBeenCalled();

    await expect(state.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: prepared.authorization.authorizationId,
      action: 'fill_only',
    })).rejects.toMatchObject({ code: 'denied' });

    const wrongPopup = await prepare(state);
    await expect(state.coordinator.commit('other-popup', {
      type: 'autofill.manual.commit',
      authorizationId: wrongPopup.authorization.authorizationId,
      action: 'fill_only',
    })).rejects.toMatchObject({ code: 'denied' });
    await expect(state.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: wrongPopup.authorization.authorizationId,
      action: 'fill_only',
    })).rejects.toMatchObject({ code: 'denied' });
  });

  it('consumes when hostile property inspection fails before request validation', async () => {
    const state = harness();
    const prepared = await prepare(state);
    const hostile = new Proxy({
      type: 'autofill.manual.commit',
      authorizationId: prepared.authorization.authorizationId,
      action: 'fill_only',
    }, {
      getOwnPropertyDescriptor(target, key) {
        if (key === 'action') throw new Error('descriptor unavailable');
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    await expect(state.coordinator.commit(POPUP_DOCUMENT, hostile))
      .rejects.toMatchObject({ code: 'denied' });
    await expect(state.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: prepared.authorization.authorizationId,
      action: 'fill_only',
    })).rejects.toMatchObject({ code: 'denied' });
  });

  it('hides save when policy or risk denies it and consumes a forged save action', async () => {
    const policy = harness();
    policy.authorizeSave.mockRejectedValue(new AppError('denied', 'disabled'));
    const policyPrepared = await prepare(policy);
    expect(policyPrepared.warning.canSave).toBe(false);
    await expect(policy.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: policyPrepared.authorization.authorizationId,
      action: 'fill_and_save',
    })).rejects.toMatchObject({ code: 'denied' });
    expect(policy.fillManual).not.toHaveBeenCalled();

    const downgrade = harness({ risk: 'https_downgrade' });
    expect((await prepare(downgrade)).warning.canSave).toBe(false);
  });

  it('saves only after an actual filled acknowledgement', async () => {
    const state = harness();
    const prepared = await prepare(state);
    await expect(state.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: prepared.authorization.authorizationId,
      action: 'fill_and_save',
    })).resolves.toEqual({ status: 'filled_and_saved' });
    expect(state.saveManualAutofillUri).toHaveBeenCalledOnce();

    const unknownFill = harness();
    unknownFill.fillManual.mockResolvedValue({ status: 'fill_outcome_unknown' } as never);
    const unknownPrepared = await prepare(unknownFill);
    await expect(unknownFill.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: unknownPrepared.authorization.authorizationId,
      action: 'fill_and_save',
    })).resolves.toEqual({ status: 'fill_outcome_unknown' });
    expect(unknownFill.saveManualAutofillUri).not.toHaveBeenCalled();
  });

  it.each([
    ['conflict', 'filled_but_save_conflict'],
    ['denied', 'filled_but_save_failed'],
    ['outcome_unknown', 'filled_but_save_outcome_unknown'],
    ['committed_unsynced', 'filled_but_save_committed_unsynced'],
  ] as const)('preserves filled while classifying a %s save failure', async (code, status) => {
    const state = harness();
    state.saveManualAutofillUri.mockRejectedValue(new AppError(code, code));
    const prepared = await prepare(state);
    await expect(state.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: prepared.authorization.authorizationId,
      action: 'fill_and_save',
    })).resolves.toEqual({ status });
  });

  it('uses an internal one-time reprompt proof and does not retain a wrong-password grant', async () => {
    const valid = harness({ requiresReprompt: true });
    const prepared = await prepare(valid);
    await expect(valid.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: prepared.authorization.authorizationId,
      action: 'fill_only',
      masterPassword: 'correct-master',
    })).resolves.toEqual({ status: 'filled' });
    expect(valid.verifyMasterPassword).toHaveBeenCalledWith('correct-master');
    expect((valid.fillManual as unknown as { mock: { calls: unknown[][] } }).mock.calls[0]![5])
      .toEqual({ assertCurrent: expect.any(Function) });

    const wrong = harness({ requiresReprompt: true });
    const wrongPrepared = await prepare(wrong);
    await expect(wrong.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: wrongPrepared.authorization.authorizationId,
      action: 'fill_only',
      masterPassword: 'wrong',
    })).rejects.toMatchObject({ code: 'reprompt_required' });
    await expect(wrong.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: wrongPrepared.authorization.authorizationId,
      action: 'fill_only',
      masterPassword: 'correct-master',
    })).rejects.toMatchObject({ code: 'denied' });
    expect(wrong.fillManual).not.toHaveBeenCalled();
  });

  it('revokes outstanding and already-redeemed authorities synchronously', async () => {
    const state = harness();
    const prepared = await prepare(state);
    state.coordinator.revokeAll();
    await expect(state.coordinator.commit(POPUP_DOCUMENT, {
      type: 'autofill.manual.commit',
      authorizationId: prepared.authorization.authorizationId,
      action: 'fill_only',
    })).rejects.toMatchObject({ code: 'denied' });
  });
});
