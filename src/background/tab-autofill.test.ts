import { describe, expect, it, vi } from 'vitest';
import { AppError } from '../core/errors.js';
import { ClientEventType } from '../core/events/client-event.js';
import type {
  AutofillCandidate,
  FillItemCandidate,
  FrameAutofillForm,
  FrameAutofillMessage,
  FrameInspection,
  TabSuggestionTarget,
} from '../messaging/protocol.js';
import {
  createTabAutofillCoordinator,
  type BrowserDocumentTarget,
  type BrowserFrame,
  type TabAutofillDeps,
} from './tab-autofill.js';
import {
  digestLoginCustomTargetPlan,
  EMPTY_LOGIN_CUSTOM_PLAN,
  EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
} from '../core/vault/login-custom-fields.js';
import { CLIENT_EVENT_BEST_EFFORT_WAIT_MS } from './client-event-best-effort.js';

const TOP_URL = 'https://example.com/login';
const EVENT_CIPHER_ID = '22222222-2222-4222-8222-222222222222';

function deferred<Value>() {
  let resolve!: (value: Value) => void;
  const promise = new Promise<Value>((done) => { resolve = done; });
  return { promise, resolve };
}

function candidate(id: string, overrides: Partial<AutofillCandidate> = {}): AutofillCandidate {
  return {
    id,
    name: `Login ${id}`,
    matchedUri: 'https://example.com',
    matchType: 0,
    favorite: false,
    ...overrides,
  };
}

function fillItem(id: string, overrides: Partial<FillItemCandidate> = {}): FillItemCandidate {
  return { id, name: `Item ${id}`, favorite: false, ...overrides };
}

function documentFrame(frameId: number, url = TOP_URL, documentId = `doc-${frameId}`): BrowserFrame {
  return { frameId, url, documentId };
}

function loginForm(formId: string, overrides: Partial<FrameAutofillForm> = {}): FrameAutofillForm {
  return { kind: 'login', formId, visible: true, customPlan: EMPTY_LOGIN_CUSTOM_PLAN, ...overrides } as FrameAutofillForm;
}

function cardForm(
  formId: string,
  roles: Array<'cardholderName' | 'number' | 'exp' | 'expMonth' | 'expYear' | 'code'>,
  overrides: Partial<FrameAutofillForm> = {},
): FrameAutofillForm {
  return { kind: 'card', formId, roles, visible: true, ...overrides } as FrameAutofillForm;
}

function identityForm(
  formId: string,
  roles: Array<
    | 'title' | 'firstName' | 'middleName' | 'lastName' | 'fullName'
    | 'address1' | 'address2' | 'address3' | 'city' | 'state' | 'postalCode'
    | 'country' | 'company' | 'email' | 'phone' | 'username'
  >,
  overrides: Partial<FrameAutofillForm> = {},
): FrameAutofillForm {
  return { kind: 'identity', formId, roles, visible: true, ...overrides } as FrameAutofillForm;
}

function inspection(
  forms: FrameAutofillForm[] = [loginForm('form-1')],
  generation = 1,
  frameUrl = TOP_URL,
): FrameInspection {
  return { frameUrl, generation, forms };
}

function defaultSendToFrame() {
  return vi.fn(async (
    _tabId: number,
    _target: BrowserDocumentTarget,
    message: FrameAutofillMessage,
  ) => message.type === 'autofill.inspectFrame' ? inspection() : { status: 'filled' });
}

function makeDeps(overrides: Partial<TabAutofillDeps> = {}): TabAutofillDeps {
  return {
    getTab: vi.fn(async () => ({ active: true, url: TOP_URL })),
    hasHostAccess: vi.fn(async () => true),
    getFrames: vi.fn(async () => [documentFrame(0)]),
    getFrame: vi.fn(async () => documentFrame(0, TOP_URL, 'doc-A')),
    sendToFrame: defaultSendToFrame(),
    authorizeFrame: vi.fn(async () => ({ assertCurrent: () => {}, defaultStrategy: 0 as const })),
    findCandidates: vi.fn(async () => []),
    findFillItems: vi.fn(async () => []),
    getLoginData: vi.fn(async () => ({})),
    getManualLoginData: vi.fn(async () => ({ login: {}, customAssignments: [] })),
    getFillData: vi.fn(async () => ({})),
    sessionGate: {
      capture: vi.fn(() => ({ generation: 1 })),
      assert: vi.fn(),
    },
    accountGate: {
      capture: vi.fn(() => ({
        serverUrl: 'https://vault.example',
        accountIdentity: 'a@example.com',
        serverGeneration: 1,
        accountGeneration: 1,
      })),
      assert: vi.fn(),
    },
    now: vi.fn(() => 1_000_000),
    ...overrides,
  };
}

const LOGIN_TARGET: TabSuggestionTarget = {
  kind: 'login',
  frameId: 0,
  formId: 'form-1',
  documentId: 'doc-A',
  generation: 1,
  customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
};

describe('tab autofill coordinator', () => {
  describe('getSuggestions', () => {
    it('preserves focus, top-frame, then encounter-order ranking', async () => {
      const now = 1_000_000;
      const focused = makeDeps({
        now: () => now,
        getFrames: async () => [documentFrame(0), documentFrame(1)],
        sendToFrame: vi.fn(async (_tabId, target) => target.frameId === 0
          ? inspection([loginForm('top-form')], 4)
          : inspection([loginForm('iframe-form', { focusedAt: now - 10_000 })], 7)),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const focusedOutcome = await createTabAutofillCoordinator(focused).getSuggestions(7);
      expect(focusedOutcome.suggestions).toEqual([expect.objectContaining({
        kind: 'login',
        id: 'c1',
        target: {
          kind: 'login', frameId: 1, formId: 'iframe-form', documentId: 'doc-1', generation: 7,
          customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
        },
      })]);

      const top = makeDeps({
        getFrames: async () => [documentFrame(0), documentFrame(1)],
        sendToFrame: vi.fn(async (_tabId, target) => target.frameId === 0
          ? inspection([loginForm('top-form')], 2)
          : inspection([loginForm('iframe-form')], 3)),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const topOutcome = await createTabAutofillCoordinator(top).getSuggestions(7);
      expect(topOutcome.suggestions[0]?.target).toEqual({
        kind: 'login', frameId: 0, formId: 'top-form', documentId: 'doc-0', generation: 2,
        customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
      });

      const order = makeDeps({
        getFrames: async () => [documentFrame(1), documentFrame(2)],
        sendToFrame: vi.fn(async (_tabId, target) => target.frameId === 1
          ? inspection([loginForm('first-form')], 5)
          : inspection([loginForm('second-form')], 6)),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const orderOutcome = await createTabAutofillCoordinator(order).getSuggestions(7);
      expect(orderOutcome.suggestions[0]?.target).toEqual({
        kind: 'login', frameId: 1, formId: 'first-form', documentId: 'doc-1', generation: 5,
        customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
      });
    });

    it('returns discriminated login, card, and identity suggestions without secret data', async () => {
      const findFillItems = vi.fn(async (kind: 'card' | 'identity') => kind === 'card'
        ? [fillItem('card-1', { subtitle: 'Visa' })]
        : [fillItem('identity-1', { subtitle: 'Ada Lovelace' })]);
      const deps = makeDeps({
        sendToFrame: vi.fn(async () => inspection([
          loginForm('login-form'),
          cardForm('card-form', ['number', 'exp']),
          identityForm('identity-form', ['fullName', 'email']),
        ], 9)),
        findCandidates: vi.fn(async () => [candidate('login-1', { username: 'ada' })]),
        findFillItems,
        getLoginData: vi.fn(async () => ({ username: 'ada', password: 'secret' })),
        getFillData: vi.fn(async () => ({ number: '4111111111111111', code: '123' })),
      });

      const outcome = await createTabAutofillCoordinator(deps).getSuggestions(7);

      expect(outcome).toEqual({
        status: 'ready',
        suggestions: [
          expect.objectContaining({ kind: 'login', id: 'login-1', target: expect.objectContaining({ kind: 'login', generation: 9 }) }),
          expect.objectContaining({
            kind: 'card', id: 'card-1', target: expect.objectContaining({ kind: 'card', roles: ['number', 'exp'], generation: 9 }),
          }),
          expect.objectContaining({
            kind: 'identity', id: 'identity-1', target: expect.objectContaining({ kind: 'identity', roles: ['fullName', 'email'], generation: 9 }),
          }),
        ],
      });
      expect(findFillItems).toHaveBeenCalledTimes(2);
      expect(deps.getLoginData).not.toHaveBeenCalled();
      expect(deps.getFillData).not.toHaveBeenCalled();
      expect(JSON.stringify(outcome)).not.toMatch(/411111|"code"|"password"|"data"/i);
    });

    it('enumerates structured items only for matching visible forms', async () => {
      const findFillItems = vi.fn(async (kind: 'card' | 'identity') => [fillItem(`${kind}-1`)]);
      const deps = makeDeps({
        sendToFrame: vi.fn(async () => inspection([
          cardForm('visible-card', ['number']),
          identityForm('hidden-identity', ['email'], { visible: false }),
        ])),
        findFillItems,
      });

      const outcome = await createTabAutofillCoordinator(deps).getSuggestions(7);

      expect(outcome.suggestions.map((item) => item.kind)).toEqual(['card']);
      expect(findFillItems).toHaveBeenCalledOnce();
      expect(findFillItems).toHaveBeenCalledWith('card');
    });

    it('withholds every target and structured item when inspection URL disagrees with browser URL', async () => {
      const findFillItems = vi.fn(async () => [fillItem('card-1')]);
      const deps = makeDeps({
        sendToFrame: vi.fn(async () => inspection([
          loginForm('spoof-login'), cardForm('spoof-card', ['number']),
        ], 1, 'https://spoof.example/')),
        findCandidates: vi.fn(async (url: string) => url === TOP_URL ? [candidate('login-1')] : [candidate('spoof')]),
        findFillItems,
      });

      const outcome = await createTabAutofillCoordinator(deps).getSuggestions(7);

      expect(outcome.suggestions).toEqual([{ kind: 'login', ...candidate('login-1') }]);
      expect(findFillItems).not.toHaveBeenCalled();
      expect(deps.findCandidates).not.toHaveBeenCalledWith('https://spoof.example/', expect.anything());
    });

    it('keeps URI matches without a target when no form or browser document identity exists', async () => {
      const sendToFrame = vi.fn(async () => inspection([]));
      const noForms = makeDeps({
        sendToFrame,
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const noFormsOutcome = await createTabAutofillCoordinator(noForms).getSuggestions(7);
      expect(noFormsOutcome.suggestions).toEqual([{ kind: 'login', ...candidate('c1') }]);

      const noDocument = makeDeps({
        getFrames: async () => [{ frameId: 0, url: TOP_URL }],
        sendToFrame,
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const noDocumentOutcome = await createTabAutofillCoordinator(noDocument).getSuggestions(7);
      expect(noDocumentOutcome.suggestions).toEqual([{ kind: 'login', ...candidate('c1') }]);
      expect(sendToFrame).toHaveBeenCalledOnce();
    });

    it('memoizes login candidates by browser URL and never consumes a reported URL', async () => {
      const findCandidates = vi.fn(async () => [candidate('c1')]);
      const deps = makeDeps({
        getFrames: async () => [documentFrame(0), documentFrame(1)],
        sendToFrame: vi.fn(async () => inspection([loginForm('form')], 1, TOP_URL)),
        findCandidates,
      });

      await createTabAutofillCoordinator(deps).getSuggestions(7);

      expect(findCandidates).toHaveBeenCalledTimes(1);
      expect(findCandidates).toHaveBeenCalledWith(TOP_URL, 0);
    });

    it('skips one unavailable frame but reports unavailable when every attempted frame fails', async () => {
      const frames = [documentFrame(0), documentFrame(1)];
      const partial = makeDeps({
        getFrames: async () => frames,
        sendToFrame: vi.fn(async (_tabId, target) => {
          if (target.frameId === 0) throw new Error('no receiving end');
          return inspection([loginForm('form')]);
        }),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      expect((await createTabAutofillCoordinator(partial).getSuggestions(7)).status).toBe('ready');

      const total = makeDeps({
        getFrames: async () => frames,
        sendToFrame: vi.fn(async () => { throw new Error('no receiving end'); }),
      });
      await expect(createTabAutofillCoordinator(total).getSuggestions(7)).resolves.toEqual({
        status: 'content_script_unavailable', suggestions: [],
      });
    });

    it('skips inaccessible cross-origin and non-host frames before inspection', async () => {
      const hasHostAccess = vi.fn(async () => false);
      const deps = makeDeps({
        hasHostAccess,
        getFrames: async () => [
          documentFrame(0),
          documentFrame(1, 'https://other.example/widget'),
          documentFrame(2, 'about:blank'),
        ],
      });

      await createTabAutofillCoordinator(deps).getSuggestions(7);

      expect(hasHostAccess).toHaveBeenCalledOnce();
      expect(deps.sendToFrame).toHaveBeenCalledOnce();
      expect(deps.sendToFrame).toHaveBeenCalledWith(
        7,
        { frameId: 0, documentId: 'doc-0' },
        { type: 'autofill.inspectFrame' },
      );
    });

    it('fails closed when the session or account changes during the scan', async () => {
      let current = true;
      const accountGate = {
        capture: vi.fn(() => ({
          serverUrl: 'https://vault.example', accountIdentity: 'a@example.com', serverGeneration: 1, accountGeneration: 1,
        })),
        assert: vi.fn(() => {
          if (!current) throw new AppError('session_expired', 'account changed');
        }),
      };
      const findCandidates = vi.fn(async () => [candidate('c1')]);
      const deps = makeDeps({
        accountGate,
        getFrames: vi.fn(async () => {
          current = false;
          return [documentFrame(0)];
        }),
        findCandidates,
      });

      await expect(createTabAutofillCoordinator(deps).getSuggestions(7)).rejects.toMatchObject({ code: 'session_expired' });
      expect(findCandidates).not.toHaveBeenCalled();
      expect(deps.sendToFrame).not.toHaveBeenCalled();
    });

    it.each([
      [{ active: false, url: TOP_URL }, 'no_eligible_tab'],
      [{ active: true }, 'site_access_unavailable'],
      [{ active: true, url: 'chrome://extensions/' }, 'restricted_page'],
    ] as const)('returns %s eligibility before frame discovery', async (tab, status) => {
      const deps = makeDeps({ getTab: vi.fn(async () => tab) });
      await expect(createTabAutofillCoordinator(deps).getSuggestions(7)).resolves.toEqual({ status, suggestions: [] });
      expect(deps.getFrames).not.toHaveBeenCalled();
    });
  });

  describe('resolveRepromptBinding', () => {
    it('uses current browser-owned tab, frame, document, URL, and exact target metadata', async () => {
      const deps = makeDeps();
      const coordinator = createTabAutofillCoordinator(deps);

      await expect(coordinator.resolveRepromptBinding(7, LOGIN_TARGET)).resolves.toEqual({
        tabId: 7,
        frameId: 0,
        targetDocumentId: 'doc-A',
        topUrl: TOP_URL,
        frameUrl: TOP_URL,
        targetKey: JSON.stringify([
          'login', 0, 'form-1', 'doc-A', 1, EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
        ]),
      });
      expect(deps.getTab).toHaveBeenCalledTimes(2);
      expect(deps.getFrame).toHaveBeenCalledTimes(2);
    });

    it('fails closed when the target document is stale or the tab is ineligible', async () => {
      const stale = createTabAutofillCoordinator(makeDeps({
        getFrame: vi.fn(async () => documentFrame(0, TOP_URL, 'doc-new')),
      }));
      await expect(stale.resolveRepromptBinding(7, LOGIN_TARGET)).resolves.toBeUndefined();

      const inactive = createTabAutofillCoordinator(makeDeps({
        getTab: vi.fn(async () => ({ active: false, url: TOP_URL })),
      }));
      await expect(inactive.resolveRepromptBinding(7, LOGIN_TARGET)).resolves.toBeUndefined();
    });
  });

  describe('fill', () => {
    it('copies TOTP only after an exact filled acknowledgement without sending the code to content', async () => {
      const receipt = Object.freeze({}) as never;
      const totpCopies = {
        prepareDirect: vi.fn(() => receipt),
        commitDirect: vi.fn(async () => ({ kind: 'copied' as const })),
        discardDirect: vi.fn(() => true),
      };
      const sendToFrame = defaultSendToFrame();
      const deps = makeDeps({
        authorizeFrame: vi.fn(async () => ({
          assertCurrent: () => {}, defaultStrategy: 0 as const, autoCopyTotp: true,
        })),
        getLoginData: vi.fn(async () => ({ password: 'credential-value' })),
        getTotpData: vi.fn(async (_id, _url, _strategy, bindFinalAuthority) => {
          bindFinalAuthority?.(() => {});
          return { code: '123456', period: 30, remaining: 12 };
        }),
        totpCopies,
        sendToFrame,
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'filled' });

      expect(totpCopies.prepareDirect).toHaveBeenCalledWith('123456', expect.any(Function), 7);
      expect(totpCopies.commitDirect).toHaveBeenCalledWith(receipt);
      expect(totpCopies.discardDirect).not.toHaveBeenCalled();
      const commit = sendToFrame.mock.calls
        .map(([, , message]) => message)
        .find((message) => message.type === 'autofill.commitLoginFill');
      expect(JSON.stringify(commit)).not.toContain('123456');
    });

    it('discards a prepared TOTP copy when content does not report an exact fill', async () => {
      const receipt = Object.freeze({}) as never;
      const totpCopies = {
        prepareDirect: vi.fn(() => receipt),
        commitDirect: vi.fn(async () => ({ kind: 'copied' as const })),
        discardDirect: vi.fn(() => true),
      };
      const sendToFrame = vi.fn(async (_tabId, _target, message: FrameAutofillMessage) => (
        message.type === 'autofill.inspectFrame' ? inspection() : { status: 'target_changed' }
      ));
      const deps = makeDeps({
        authorizeFrame: vi.fn(async () => ({
          assertCurrent: () => {}, defaultStrategy: 0 as const, autoCopyTotp: true,
        })),
        getLoginData: vi.fn(async () => ({ password: 'credential-value' })),
        getTotpData: vi.fn(async () => ({ code: '123456', period: 30, remaining: 12 })),
        totpCopies,
        sendToFrame,
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'target_changed' });
      expect(totpCopies.commitDirect).not.toHaveBeenCalled();
      expect(totpCopies.discardDirect).toHaveBeenCalledWith(receipt);
    });

    it('keeps login filling successful when no TOTP can be released', async () => {
      const totpCopies = {
        prepareDirect: vi.fn(() => Object.freeze({}) as never),
        commitDirect: vi.fn(async () => ({ kind: 'copied' as const })),
        discardDirect: vi.fn(() => true),
      };
      const deps = makeDeps({
        authorizeFrame: vi.fn(async () => ({
          assertCurrent: () => {}, defaultStrategy: 0 as const, autoCopyTotp: true,
        })),
        getLoginData: vi.fn(async () => ({ password: 'credential-value' })),
        getTotpData: vi.fn(async () => { throw new AppError('denied', 'no TOTP'); }),
        totpCopies,
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'filled' });
      expect(totpCopies.prepareDirect).not.toHaveBeenCalled();
      expect(totpCopies.commitDirect).not.toHaveBeenCalled();
    });

    it('discards TOTP and withholds the fill when navigation wins during TOTP retrieval', async () => {
      const receipt = Object.freeze({}) as never;
      const totpCopies = {
        prepareDirect: vi.fn(() => receipt),
        commitDirect: vi.fn(async () => ({ kind: 'copied' as const })),
        discardDirect: vi.fn(() => true),
      };
      const getFrame = vi.fn()
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-A'))
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-A'))
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-A'))
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-B'));
      const deps = makeDeps({
        getFrame,
        authorizeFrame: vi.fn(async () => ({
          assertCurrent: () => {}, defaultStrategy: 0 as const, autoCopyTotp: true,
        })),
        getLoginData: vi.fn(async () => ({ password: 'credential-value' })),
        getTotpData: vi.fn(async () => ({ code: '123456', period: 30, remaining: 12 })),
        totpCopies,
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'target_changed' });
      expect(totpCopies.discardDirect).toHaveBeenCalledWith(receipt);
      expect(totpCopies.commitDirect).not.toHaveBeenCalled();
      expect(deps.sendToFrame).toHaveBeenCalledOnce();
    });

    it('withholds the final frame message when the durable release checkpoint fails', async () => {
      const checkpoint = vi.fn(async () => {
        throw new AppError('locked', 'checkpoint unavailable');
      });
      const vaultReleaseGate = {
        capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} } as never)),
        checkpoint,
        assertAuthorities: vi.fn((_proof: never, assertCurrent: () => void) => assertCurrent()),
        assert: vi.fn(),
        settlePendingAction: vi.fn(async () => undefined),
      };
      const deps = makeDeps({
        vaultReleaseGate,
        getLoginData: vi.fn(async () => ({
          login: { username: 'ada', password: 'secret' },
          customAssignments: [],
        })),
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'login-1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'vault_locked' });

      expect(checkpoint).toHaveBeenCalledOnce();
      expect(vaultReleaseGate.settlePendingAction).toHaveBeenCalledOnce();
      expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
      expect(deps.sendToFrame).toHaveBeenCalledOnce();
    });

    it('rechecks account, site policy, and external authority after the checkpoint await', async () => {
      let authorized = true;
      const pending = deferred<never>();
      const vaultReleaseGate = {
        capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} } as never)),
        checkpoint: vi.fn(() => pending.promise),
        assertAuthorities: vi.fn((_proof: never, assertCurrent: () => void) => assertCurrent()),
        assert: vi.fn(),
      };
      const deps = makeDeps({
        vaultReleaseGate,
        authorizeFrame: vi.fn(async () => ({
          assertCurrent: () => {
            if (!authorized) throw new AppError('denied', 'policy changed');
          },
          defaultStrategy: 0 as const,
        })),
        getLoginData: vi.fn(async () => ({
          login: { username: 'ada', password: 'secret' },
          customAssignments: [],
        })),
      });
      const fill = createTabAutofillCoordinator(deps).fill(7, 'login-1', LOGIN_TARGET);
      await vi.waitFor(() => expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce());
      authorized = false;
      pending.resolve({} as never);

      await expect(fill).resolves.toEqual({ status: 'no_longer_matched' });
      expect(vaultReleaseGate.assertAuthorities).toHaveBeenCalledOnce();
      expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
      expect(deps.sendToFrame).toHaveBeenCalledOnce();
    });

    it('rechecks result-bound login authority after the checkpoint await', async () => {
      let current = true;
      const pending = deferred<never>();
      const vaultReleaseGate = {
        capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} } as never)),
        checkpoint: vi.fn(() => pending.promise),
        assertAuthorities: vi.fn((_proof: never, assertCurrent: () => void) => assertCurrent()),
        assert: vi.fn(),
      };
      const deps = makeDeps({
        vaultReleaseGate,
        getLoginData: vi.fn(async (
          _cipherId,
          _frameUrl,
          _strategy,
          _customPlan,
          _assertReprompt,
          bindFinalAuthority,
        ) => {
          bindFinalAuthority?.(() => {
            if (!current) throw new AppError('denied', 'vault result changed');
          });
          return { login: { username: 'ada', password: 'secret' }, customAssignments: [] };
        }),
      });
      const fill = createTabAutofillCoordinator(deps).fill(7, 'login-1', LOGIN_TARGET);
      await vi.waitFor(() => expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce());
      current = false;
      pending.resolve({} as never);

      await expect(fill).resolves.toEqual({ status: 'no_longer_matched' });
      expect(vaultReleaseGate.assertAuthorities).toHaveBeenCalledOnce();
      expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
      expect(deps.sendToFrame).toHaveBeenCalledOnce();
    });

    it('captures session and account leases before reading browser state', async () => {
      const deps = makeDeps();

      await createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET);

      const firstTabRead = (deps.getTab as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!;
      expect((deps.sessionGate.capture as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]).toBeLessThan(firstTabRead);
      expect((deps.accountGate.capture as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]).toBeLessThan(firstTabRead);
    });

    it('re-inspects the exact document before releasing and committing login data', async () => {
      const getLoginData = vi.fn(async () => ({ username: 'ada', password: 'secret', totp: 'must-not-cross' }));
      const sendToFrame = defaultSendToFrame();
      const deps = makeDeps({ getLoginData, sendToFrame });

      const outcome = await createTabAutofillCoordinator(deps).fill(7, 'login-1', LOGIN_TARGET);

      expect(outcome).toEqual({ status: 'filled' });
      expect(sendToFrame).toHaveBeenNthCalledWith(
        1, 7, { frameId: 0, documentId: 'doc-A' }, { type: 'autofill.inspectFrame' },
      );
      expect(getLoginData).toHaveBeenCalledWith(
        'login-1', TOP_URL, 0, EMPTY_LOGIN_CUSTOM_PLAN, undefined, expect.any(Function),
      );
      expect(sendToFrame).toHaveBeenNthCalledWith(2, 7, { frameId: 0, documentId: 'doc-A' }, {
        type: 'autofill.commitLoginFill',
        formId: 'form-1',
        expectedFrameUrl: TOP_URL,
        expectedGeneration: 1,
        login: { username: 'ada', password: 'secret' },
        customPlan: EMPTY_LOGIN_CUSTOM_PLAN,
        customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
        customAssignments: [],
      });
      expect(sendToFrame.mock.invocationCallOrder[0]).toBeLessThan(getLoginData.mock.invocationCallOrder[0]!);
      expect(getLoginData.mock.invocationCallOrder[0]).toBeLessThan(sendToFrame.mock.invocationCallOrder[1]!);
    });

    it('commits an autofill event only after an exact filled acknowledgement', async () => {
      const receipt = Object.freeze({}) as never;
      const prepare = vi.fn(async () => receipt);
      const commit = vi.fn(async () => ({ kind: 'enqueued' as const }));
      const sendToFrame = defaultSendToFrame();
      const deps = makeDeps({
        clientEvents: { prepare, commit },
        sendToFrame,
        getLoginData: vi.fn(async () => ({
          login: { username: 'ada', password: 'secret' },
          customAssignments: [],
        })),
      });

      await expect(createTabAutofillCoordinator(deps).fill(
        7,
        EVENT_CIPHER_ID,
        LOGIN_TARGET,
      )).resolves.toEqual({ status: 'filled' });

      expect(prepare).toHaveBeenCalledWith({
        type: ClientEventType.Cipher_ClientAutofilled,
        cipherId: EVENT_CIPHER_ID,
      });
      expect(commit).toHaveBeenCalledWith(receipt);
      expect(prepare.mock.invocationCallOrder[0]).toBeLessThan(sendToFrame.mock.invocationCallOrder[1]!);
      expect(sendToFrame.mock.invocationCallOrder[1]).toBeLessThan(commit.mock.invocationCallOrder[0]!);
    });

    it('does not commit an autofill event for a non-filled content acknowledgement', async () => {
      const receipt = Object.freeze({}) as never;
      const commit = vi.fn(async () => ({ kind: 'enqueued' as const }));
      const deps = makeDeps({
        clientEvents: { prepare: vi.fn(async () => receipt), commit },
        sendToFrame: vi.fn(async (_tabId, _target, message: FrameAutofillMessage) => (
          message.type === 'autofill.inspectFrame'
            ? inspection()
            : { status: 'target_changed' }
        )),
      });

      await expect(createTabAutofillCoordinator(deps).fill(
        7,
        EVENT_CIPHER_ID,
        LOGIN_TARGET,
      )).resolves.toEqual({ status: 'target_changed' });
      expect(commit).not.toHaveBeenCalled();
    });

    it('does not commit an autofill event for a non-exact filled acknowledgement', async () => {
      const receipt = Object.freeze({}) as never;
      const commit = vi.fn(async () => ({ kind: 'enqueued' as const }));
      const deps = makeDeps({
        clientEvents: { prepare: vi.fn(async () => receipt), commit },
        sendToFrame: vi.fn(async (_tabId, _target, message: FrameAutofillMessage) => (
          message.type === 'autofill.inspectFrame'
            ? inspection()
            : { status: 'filled', injected: true }
        )),
      });

      await expect(createTabAutofillCoordinator(deps).fill(
        7,
        EVENT_CIPHER_ID,
        LOGIN_TARGET,
      )).resolves.toEqual({ status: 'filled' });
      expect(commit).not.toHaveBeenCalled();
    });

    it('keeps autofill successful when event preparation or commit fails', async () => {
      const prepareFailure = makeDeps({
        clientEvents: {
          prepare: vi.fn(async () => { throw new Error('event authority unavailable'); }),
          commit: vi.fn(async () => ({ kind: 'enqueued' as const })),
        },
      });
      await expect(createTabAutofillCoordinator(prepareFailure).fill(
        7,
        'not-a-canonical-event-id',
        LOGIN_TARGET,
      )).resolves.toEqual({ status: 'filled' });

      const commitFailure = makeDeps({
        clientEvents: {
          prepare: vi.fn(async () => Object.freeze({}) as never),
          commit: vi.fn(async () => { throw new Error('event queue unavailable'); }),
        },
      });
      await expect(createTabAutofillCoordinator(commitFailure).fill(
        7,
        EVENT_CIPHER_ID,
        LOGIN_TARGET,
      )).resolves.toEqual({ status: 'filled' });
    });

    it('does not let hanging event preparation block autofill', async () => {
      vi.useFakeTimers();
      try {
        const prepare = vi.fn(() => new Promise<never>(() => {}));
        const deps = makeDeps({
          clientEvents: {
            prepare,
            commit: vi.fn(async () => ({ kind: 'enqueued' as const })),
          },
        });
        const fill = createTabAutofillCoordinator(deps).fill(
          7,
          EVENT_CIPHER_ID,
          LOGIN_TARGET,
        );
        await vi.waitFor(() => expect(prepare).toHaveBeenCalledOnce());
        await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS);
        await expect(fill).resolves.toEqual({ status: 'filled' });
      } finally {
        vi.useRealTimers();
      }
    });

    it('rechecks the browser document after asynchronous event preparation', async () => {
      const pending = deferred<never>();
      const commit = vi.fn(async () => ({ kind: 'enqueued' as const }));
      const getFrame = vi.fn()
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-A'))
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-A'))
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-B'));
      const deps = makeDeps({
        clientEvents: { prepare: vi.fn(() => pending.promise), commit },
        getFrame,
      });
      const fill = createTabAutofillCoordinator(deps).fill(7, EVENT_CIPHER_ID, LOGIN_TARGET);
      await vi.waitFor(() => expect(deps.clientEvents?.prepare).toHaveBeenCalledOnce());
      pending.resolve(Object.freeze({}) as never);

      await expect(fill).resolves.toEqual({ status: 'target_changed' });
      expect(deps.sendToFrame).toHaveBeenCalledOnce();
      expect(commit).not.toHaveBeenCalled();
    });

    it('uses the same exact ACK rule for structured fills', async () => {
      const receipt = Object.freeze({}) as never;
      const commit = vi.fn(async () => ({ kind: 'enqueued' as const }));
      const target: TabSuggestionTarget = {
        kind: 'card', frameId: 0, documentId: 'doc-A', formId: 'card-form', generation: 3,
        roles: ['number'],
      };
      const deps = makeDeps({
        clientEvents: { prepare: vi.fn(async () => receipt), commit },
        getFillData: vi.fn(async () => ({ number: '4111111111111111' })),
        sendToFrame: vi.fn(async (_tabId, _target, message: FrameAutofillMessage) => (
          message.type === 'autofill.inspectFrame'
            ? inspection([cardForm('card-form', ['number'])], 3)
            : { status: 'filled' }
        )),
      });

      await expect(createTabAutofillCoordinator(deps).fill(
        7,
        EVENT_CIPHER_ID,
        target,
      )).resolves.toEqual({ status: 'filled' });
      expect(commit).toHaveBeenCalledWith(receipt);
    });

    it('keeps a reprompt authorization in the worker and passes only its live assertion to secret reads', async () => {
      const grantAssert = vi.fn();
      const getLoginData = vi.fn(async (...args: Parameters<TabAutofillDeps['getLoginData']>) => {
        args[4]?.();
        return { login: { password: 'secret' }, customAssignments: [] };
      });
      const sendToFrame = defaultSendToFrame();
      const deps = makeDeps({ getLoginData, sendToFrame });

      await expect(createTabAutofillCoordinator(deps).fill(
        7,
        'login-1',
        LOGIN_TARGET,
        undefined,
        { assertCurrent: grantAssert },
      )).resolves.toEqual({ status: 'filled' });

      expect(getLoginData).toHaveBeenCalledWith(
        'login-1',
        TOP_URL,
        0,
        EMPTY_LOGIN_CUSTOM_PLAN,
        expect.any(Function),
        expect.any(Function),
      );
      expect(grantAssert).toHaveBeenCalled();
      expect(JSON.stringify(sendToFrame.mock.calls)).not.toContain('authorizationId');
      expect(JSON.stringify(sendToFrame.mock.calls)).not.toContain('masterPassword');
    });

    it('binds Popup login fill to the freshly inspected custom plan and sends minimal assignments', async () => {
      const customPlan = {
        version: 2 as const,
        generation: 3,
        targets: [{ fieldId: 'private-1', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'department' }] }],
      };
      const customPlanDigest = await digestLoginCustomTargetPlan(customPlan);
      const target: TabSuggestionTarget = { ...LOGIN_TARGET, customPlanDigest };
      const getLoginData = vi.fn(async () => ({
        login: { username: 'ada', password: 'secret', totp: 'must-not-cross' },
        customAssignments: [{ fieldId: 'private-1', value: 'engineering' }],
        customFieldName: 'must-not-cross',
      }));
      const sendToFrame = vi.fn(async (_tabId, _target, message: FrameAutofillMessage) => (
        message.type === 'autofill.inspectFrame'
          ? inspection([loginForm('form-1', { customPlan })])
          : { status: 'filled' }
      ));
      const deps = makeDeps({ getLoginData, sendToFrame });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'login-1', target))
        .resolves.toEqual({ status: 'filled' });
      expect(getLoginData).toHaveBeenCalledWith(
        'login-1', TOP_URL, 0, customPlan, undefined, expect.any(Function),
      );
      expect(sendToFrame).toHaveBeenNthCalledWith(2, 7, { frameId: 0, documentId: 'doc-A' }, {
        type: 'autofill.commitLoginFill',
        formId: 'form-1',
        expectedFrameUrl: TOP_URL,
        expectedGeneration: 1,
        login: { username: 'ada', password: 'secret' },
        customPlan,
        customPlanDigest,
        customAssignments: [{ fieldId: 'private-1', value: 'engineering' }],
      });
      expect(JSON.stringify(sendToFrame.mock.calls[1]?.[2])).not.toContain('customFieldName');
      expect(JSON.stringify(sendToFrame.mock.calls[1]?.[2])).not.toContain('totp');
    });

    it('rejects a Popup custom-plan digest mismatch before decrypting any login secret', async () => {
      const changedPlan = {
        version: 2 as const,
        generation: 2,
        targets: [{ fieldId: 'changed', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'realm' }] }],
      };
      const deps = makeDeps({
        sendToFrame: vi.fn(async () => inspection([loginForm('form-1', { customPlan: changedPlan })])),
      });
      await expect(createTabAutofillCoordinator(deps).fill(7, 'login-1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'target_changed' });
      expect(deps.getLoginData).not.toHaveBeenCalled();
    });

    it('requests and commits only the card roles revalidated by fresh inspection', async () => {
      const target: TabSuggestionTarget = {
        kind: 'card', frameId: 0, documentId: 'doc-A', formId: 'card-form', generation: 8, roles: ['number'],
      };
      const getFillData = vi.fn(async () => ({
        number: '4111111111111111', code: '123', expMonth: '09', expYear: '2030', email: 'must-not-cross',
      }));
      const sendToFrame = vi.fn(async (_tabId, _target, message: FrameAutofillMessage) => (
        message.type === 'autofill.inspectFrame'
          ? inspection([cardForm('card-form', ['number'])], 8)
          : { status: 'filled' }
      ));
      const deps = makeDeps({ getFillData, sendToFrame });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'card-1', target))
        .resolves.toEqual({ status: 'filled' });

      expect(getFillData).toHaveBeenCalledWith(
        'card-1', 'card', ['number'], undefined, expect.any(Function),
      );
      expect(sendToFrame).toHaveBeenNthCalledWith(2, 7, { frameId: 0, documentId: 'doc-A' }, {
        type: 'autofill.commitStructuredFill',
        kind: 'card',
        formId: 'card-form',
        roles: ['number'],
        expectedFrameUrl: TOP_URL,
        expectedGeneration: 8,
        data: { number: '4111111111111111' },
      });
    });

    it('expands only the identity fullName composite into its three backing fields', async () => {
      const target: TabSuggestionTarget = {
        kind: 'identity', frameId: 0, documentId: 'doc-A', formId: 'identity-form', generation: 3, roles: ['fullName'],
      };
      const getFillData = vi.fn(async () => ({
        title: 'Countess', firstName: 'Ada', middleName: 'Byron', lastName: 'Lovelace',
        email: 'must-not-cross@example.com',
      }));
      const sendToFrame = vi.fn(async (_tabId, _target, message: FrameAutofillMessage) => (
        message.type === 'autofill.inspectFrame'
          ? inspection([identityForm('identity-form', ['fullName'])], 3)
          : { status: 'filled' }
      ));
      const deps = makeDeps({ getFillData, sendToFrame });

      await createTabAutofillCoordinator(deps).fill(7, 'identity-1', target);

      expect(getFillData).toHaveBeenCalledWith(
        'identity-1', 'identity', ['fullName'], undefined, expect.any(Function),
      );
      expect(sendToFrame).toHaveBeenNthCalledWith(2, 7, { frameId: 0, documentId: 'doc-A' }, expect.objectContaining({
        data: { firstName: 'Ada', middleName: 'Byron', lastName: 'Lovelace' },
      }));
    });

    it.each([
      ['generation', { ...LOGIN_TARGET, generation: 99 }, inspection([loginForm('form-1')], 1)],
      ['form id', { ...LOGIN_TARGET, formId: 'forged' }, inspection([loginForm('form-1')], 1)],
      ['kind', { ...LOGIN_TARGET, kind: 'login' }, inspection([cardForm('form-1', ['number'])], 1)],
    ] as const)('rejects a stale or forged %s before secret retrieval', async (_label, target, freshInspection) => {
      const getLoginData = vi.fn(async () => ({ password: 'secret' }));
      const deps = makeDeps({
        sendToFrame: vi.fn(async () => freshInspection),
        getLoginData,
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', target as TabSuggestionTarget))
        .resolves.toEqual({ status: 'target_changed' });
      expect(getLoginData).not.toHaveBeenCalled();
      expect(deps.getFillData).not.toHaveBeenCalled();
    });

    it('rejects forged structured roles before retrieving any card data', async () => {
      const target: TabSuggestionTarget = {
        kind: 'card', frameId: 0, documentId: 'doc-A', formId: 'card-form', generation: 2, roles: ['number', 'code'],
      };
      const getFillData = vi.fn(async () => ({ number: '4111', code: '123' }));
      const deps = makeDeps({
        sendToFrame: vi.fn(async () => inspection([cardForm('card-form', ['number'])], 2)),
        getFillData,
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'card-1', target))
        .resolves.toEqual({ status: 'target_changed' });
      expect(getFillData).not.toHaveBeenCalled();
    });

    it.each([
      ['duplicate', ['number', 'number']],
      ['non-canonical order', ['code', 'number']],
      ['unknown', ['number', 'ssn']],
    ] as const)('rejects a %s role list at the coordinator boundary', async (_label, roles) => {
      const target = {
        kind: 'card', frameId: 0, documentId: 'doc-A', formId: 'card-form', generation: 1, roles,
      } as unknown as TabSuggestionTarget;
      const deps = makeDeps();

      await expect(createTabAutofillCoordinator(deps).fill(7, 'card-1', target))
        .resolves.toEqual({ status: 'target_changed' });
      expect(deps.sessionGate.capture).not.toHaveBeenCalled();
      expect(deps.getFillData).not.toHaveBeenCalled();
    });

    it('rejects an inspection URL mismatch before retrieving secrets', async () => {
      const deps = makeDeps({
        sendToFrame: vi.fn(async () => inspection([loginForm('form-1')], 1, 'https://navigated.example/')),
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'target_changed' });
      expect(deps.getLoginData).not.toHaveBeenCalled();
    });

    it('rejects a changed document before inspection or secret retrieval', async () => {
      const deps = makeDeps({ getFrame: vi.fn(async () => documentFrame(0, TOP_URL, 'doc-B')) });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'target_changed' });
      expect(deps.sendToFrame).not.toHaveBeenCalled();
      expect(deps.getLoginData).not.toHaveBeenCalled();
    });

    it('rejects a navigation after inspection and before secret retrieval', async () => {
      const getFrame = vi.fn()
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-A'))
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-B'));
      const deps = makeDeps({ getFrame });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'target_changed' });
      expect(deps.getLoginData).not.toHaveBeenCalled();
      expect(deps.sendToFrame).toHaveBeenCalledOnce();
    });

    it('does not commit when the document changes after secret retrieval', async () => {
      const getFrame = vi.fn()
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-A'))
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-A'))
        .mockResolvedValueOnce(documentFrame(0, TOP_URL, 'doc-B'));
      const sendToFrame = defaultSendToFrame();
      const deps = makeDeps({
        getFrame,
        getLoginData: vi.fn(async () => ({ password: 'secret' })),
        sendToFrame,
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'target_changed' });
      expect(deps.getLoginData).toHaveBeenCalledOnce();
      expect(sendToFrame).toHaveBeenCalledOnce();
    });

    it('does not commit when the top document changes after secret retrieval', async () => {
      const getTab = vi.fn()
        .mockResolvedValueOnce({ active: true, url: TOP_URL })
        .mockResolvedValueOnce({ active: true, url: TOP_URL })
        .mockResolvedValueOnce({ active: true, url: 'https://example.com/other' });
      const sendToFrame = defaultSendToFrame();
      const deps = makeDeps({ getTab, sendToFrame });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'target_changed' });
      expect(sendToFrame).toHaveBeenCalledOnce();
    });

    it('does not retrieve secrets when policy is revoked after inspection', async () => {
      let current = true;
      const authorizeFrame = vi.fn(async () => ({
        defaultStrategy: 0 as const,
        assertCurrent: () => {
          if (!current) throw new AppError('denied', 'policy changed');
        },
      }));
      const deps = makeDeps({
        authorizeFrame,
        sendToFrame: vi.fn(async () => {
          current = false;
          return inspection();
        }),
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'no_longer_matched' });
      expect(deps.getLoginData).not.toHaveBeenCalled();
    });

    it.each(['session', 'account'] as const)('does not commit after the %s lease becomes stale', async (gate) => {
      let current = true;
      const sessionGate = {
        capture: vi.fn(() => ({ generation: 1 })),
        assert: vi.fn(() => {
          if (!current && gate === 'session') throw new AppError('locked', 'session changed');
        }),
      };
      const accountGate = {
        capture: vi.fn(() => ({
          serverUrl: 'https://vault.example', accountIdentity: 'a@example.com', serverGeneration: 1, accountGeneration: 1,
        })),
        assert: vi.fn(() => {
          if (!current && gate === 'account') throw new AppError('session_expired', 'account changed');
        }),
      };
      const sendToFrame = defaultSendToFrame();
      const deps = makeDeps({
        sessionGate,
        accountGate,
        getLoginData: vi.fn(async () => {
          current = false;
          return { password: 'secret' };
        }),
        sendToFrame,
      });

      const outcome = await createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET);

      expect(outcome.status).toBe(gate === 'session' ? 'vault_locked' : 'no_longer_matched');
      expect(sendToFrame).toHaveBeenCalledOnce();
    });

    it('carries an external intent lease fence through secret retrieval and final commit', async () => {
      let externalCurrent = true;
      const assertExternalCurrent = vi.fn(() => {
        if (!externalCurrent) throw new AppError('denied', 'intent lease changed');
      });
      const sendToFrame = defaultSendToFrame();
      const deps = makeDeps({
        getLoginData: vi.fn(async () => {
          externalCurrent = false;
          return { password: 'must-not-commit' };
        }),
        sendToFrame,
      });

      await expect(createTabAutofillCoordinator(deps).fill(
        7,
        'c1',
        LOGIN_TARGET,
        assertExternalCurrent,
      )).resolves.toEqual({ status: 'no_longer_matched' });
      expect(assertExternalCurrent).toHaveBeenCalled();
      expect(sendToFrame).toHaveBeenCalledOnce();
    });

    it.each([
      ['reprompt_required', 'reprompt_required'],
      ['locked', 'vault_locked'],
      ['sync_required', 'sync_required'],
      ['denied', 'no_longer_matched'],
    ] as const)('maps %s secret refusal to %s', async (code, status) => {
      const deps = makeDeps({
        getLoginData: vi.fn(async () => { throw new AppError(code, 'blocked'); }),
      });
      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET)).resolves.toEqual({ status });
      expect(deps.sendToFrame).toHaveBeenCalledOnce();
    });

    it('denies a cross-origin frame without permanent host access', async () => {
      const target: TabSuggestionTarget = { ...LOGIN_TARGET, frameId: 1 };
      const deps = makeDeps({
        getFrame: vi.fn(async () => documentFrame(1, 'https://other.example/widget', 'doc-A')),
        hasHostAccess: vi.fn(async () => false),
      });

      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', target))
        .resolves.toEqual({ status: 'content_script_unavailable' });
      expect(deps.sendToFrame).not.toHaveBeenCalled();
      expect(deps.getLoginData).not.toHaveBeenCalled();
    });

    it('reports content script loss during inspection or commit without leaking to another document', async () => {
      const duringInspection = makeDeps({
        sendToFrame: vi.fn(async () => { throw new Error('No document with id doc-A in tab 7'); }),
      });
      await expect(createTabAutofillCoordinator(duringInspection).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'content_script_unavailable' });
      expect(duringInspection.getLoginData).not.toHaveBeenCalled();

      const duringCommit = makeDeps({
        sendToFrame: vi.fn(async (_tabId, _target, message: FrameAutofillMessage) => {
          if (message.type === 'autofill.inspectFrame') return inspection();
          throw new Error('Could not establish connection. Receiving end does not exist.');
        }),
      });
      await expect(createTabAutofillCoordinator(duringCommit).fill(7, 'c1', LOGIN_TARGET))
        .resolves.toEqual({ status: 'content_script_unavailable' });
    });

    it('rethrows an unexpected delivery failure', async () => {
      const deps = makeDeps({
        sendToFrame: vi.fn(async () => { throw new TypeError('commit is not a function'); }),
      });
      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', LOGIN_TARGET))
        .rejects.toThrow('commit is not a function');
    });
  });
});

describe('manual tab autofill', () => {
  it('commits the autofill event after a manual fill receives an exact filled acknowledgement', async () => {
    const receipt = Object.freeze({}) as never;
    const commit = vi.fn(async () => ({ kind: 'enqueued' as const }));
    const deps = makeDeps({
      clientEvents: { prepare: vi.fn(async () => receipt), commit },
      getManualLoginData: vi.fn(async () => ({
        login: { password: 'credential-value' },
        customAssignments: [],
      })),
    });

    await expect(createTabAutofillCoordinator(deps).fillManual(
      7,
      EVENT_CIPHER_ID,
      LOGIN_TARGET as Extract<TabSuggestionTarget, { kind: 'login' }>,
      {
        cipherRevision: '2026-09-01T00:00:00.0000001Z',
        uriDigest: 'a'.repeat(64),
        risk: 'no_match',
        requiresReprompt: false,
      },
      () => {},
    )).resolves.toEqual({ status: 'filled' });
    expect(commit).toHaveBeenCalledWith(receipt);
  });

  it('discovers one visible login target without consulting URI candidates', async () => {
    const deps = makeDeps({
      getFrames: vi.fn(async () => [documentFrame(0, TOP_URL, 'doc-A')]),
      getFrame: vi.fn(async () => documentFrame(0, TOP_URL, 'doc-A')),
      findCandidates: vi.fn(async () => { throw new Error('must not run'); }),
    });
    const resolved = await createTabAutofillCoordinator(deps).resolveManualLoginTarget(7);
    expect(resolved).toMatchObject({
      tabId: 7,
      frameId: 0,
      targetDocumentId: 'doc-A',
      target: { kind: 'login', formId: 'form-1', documentId: 'doc-A', generation: 1 },
    });
    expect(deps.findCandidates).not.toHaveBeenCalled();
  });

  it('fails closed on multiple forms and permits one authorized cross-origin fill target', async () => {
    const multiple = makeDeps({
      getFrames: vi.fn(async () => [documentFrame(0, TOP_URL, 'doc-A')]),
      sendToFrame: vi.fn(async () => inspection([loginForm('one'), loginForm('two')])),
    });
    await expect(createTabAutofillCoordinator(multiple).resolveManualLoginTarget(7))
      .resolves.toBeUndefined();

    const crossUrl = 'https://accounts.example.net/login';
    const cross = makeDeps({
      getFrames: vi.fn(async () => [documentFrame(1, crossUrl, 'doc-X')]),
      getFrame: vi.fn(async () => documentFrame(1, crossUrl, 'doc-X')),
      sendToFrame: vi.fn(async () => inspection([loginForm('cross')], 3, crossUrl)),
      hasHostAccess: vi.fn(async () => true),
    });
    await expect(createTabAutofillCoordinator(cross).resolveManualLoginTarget(7))
      .resolves.toMatchObject({
        topUrl: TOP_URL,
        frameUrl: crossUrl,
        target: { formId: 'cross', documentId: 'doc-X' },
      });
  });

  it('reports an unknown result when the final manual fill acknowledgement is lost', async () => {
    const getManualLoginData = vi.fn(async () => ({
      login: { password: 'credential-value' },
      customAssignments: [],
    }));
    const deps = makeDeps({
      getManualLoginData,
      sendToFrame: vi.fn(async (_tabId, _target, message: FrameAutofillMessage) => {
        if (message.type === 'autofill.inspectFrame') return inspection();
        throw new Error('Could not establish connection. Receiving end does not exist.');
      }),
    });
    const outcome = await createTabAutofillCoordinator(deps).fillManual(
      7,
      'c1',
      LOGIN_TARGET as Extract<TabSuggestionTarget, { kind: 'login' }>,
      {
        cipherRevision: '2026-09-01T00:00:00.0000001Z',
        uriDigest: 'a'.repeat(64),
        risk: 'no_match',
        requiresReprompt: false,
      },
      () => {},
    );
    expect(outcome).toEqual({ status: 'fill_outcome_unknown' });
    expect(getManualLoginData).toHaveBeenCalledOnce();
    expect(deps.getLoginData).not.toHaveBeenCalled();
  });
});
