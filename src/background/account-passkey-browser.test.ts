import { afterEach, describe, expect, it, vi } from 'vitest';
import { bytesToBase64Url } from '../core/crypto/encoding.js';
import { accountPasskeyConnectorUrl } from '../core/session/account-passkey.js';
import {
  AccountPasskeyBrowserOrchestrator,
  performAccountPasskeyCeremony,
  type AccountPasskeyBrowserApi,
} from './account-passkey-browser.js';
import type { AccountPasskeySubmitOutcome } from './account-passkey-coordinator.js';

const SERVER = 'https://vault.example/base/';
const CONNECTOR_URL = accountPasskeyConnectorUrl(SERVER);
const ATTEMPT = '11111111-1111-4111-8111-111111111111';

function ceremony() {
  return Object.freeze({
    attemptId: ATTEMPT,
    options: Object.freeze({
      challenge: bytesToBase64Url(new Uint8Array(32).fill(1)),
      timeout: 60_000,
      rpId: 'vault.example',
      allowCredentials: Object.freeze([Object.freeze({
        id: bytesToBase64Url(new Uint8Array(32).fill(2)),
        type: 'public-key' as const,
        transports: Object.freeze(['internal' as const]),
      })]),
      userVerification: 'required' as const,
    }),
    prfSalt: bytesToBase64Url(new Uint8Array(32).fill(3)),
    expiresAt: Date.now() + 60_000,
  });
}

function assertionResult() {
  return {
    assertion: {
      id: bytesToBase64Url(new Uint8Array(32).fill(2)),
      rawId: bytesToBase64Url(new Uint8Array(32).fill(2)),
      type: 'public-key' as const,
      extensions: {},
      response: {
        authenticatorData: bytesToBase64Url(new Uint8Array(37).fill(4)),
        signature: bytesToBase64Url(new Uint8Array(64).fill(5)),
        clientDataJSON: bytesToBase64Url(new Uint8Array(32).fill(6)),
        userHandle: bytesToBase64Url(new Uint8Array(16).fill(7)),
      },
    },
    prfOutput: Array.from(new Uint8Array(32).fill(8)),
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => { resolve = settle; });
  return { promise, resolve };
}

function harness(overrides: {
  execute?: ReturnType<typeof vi.fn>;
  frame?: { frameId: number; documentId: string; url: string };
  attempt?: unknown;
  startupStatus?: unknown;
  authState?: 'loggedOut' | 'locked' | 'unlocked';
  hasHostAccess?: boolean;
  submitOutcome?: AccountPasskeySubmitOutcome;
} = {}) {
  const frame = overrides.frame ?? { documentId: 'document-a', url: CONNECTOR_URL };
  const executeScript = overrides.execute ?? vi.fn(async () => ([{
    frameId: 0,
    documentId: 'document-a',
    result: { kind: 'success', result: assertionResult() },
  }]));
  const remove = vi.fn(async () => undefined);
  const create = vi.fn(async () => ({ id: 7, url: CONNECTOR_URL }));
  const query = vi.fn(async () => []);
  const createWindow = vi.fn(async () => ({ id: 9 }));
  const browser: AccountPasskeyBrowserApi = {
    tabs: { create, query, remove },
    webNavigation: { getFrame: vi.fn(async () => frame) },
    scripting: {
      executeScript: executeScript as unknown as AccountPasskeyBrowserApi['scripting']['executeScript'],
    },
    permissions: { contains: vi.fn(async () => overrides.hasHostAccess ?? true) },
    windows: { create: createWindow },
  };
  const connector = {
    tabId: 7,
    frameId: 0 as const,
    documentId: 'document-a',
    url: CONNECTOR_URL,
    origin: 'https://vault.example',
  };
  let attempt = overrides.attempt;
  let observedSubmitPrf: number[] | undefined;
  const begin = vi.fn(async () => ceremony());
  const resume = vi.fn(async () => ceremony());
  const submit = vi.fn(async (
    _connector: unknown,
    _attemptId: string,
    result: ReturnType<typeof assertionResult>,
  ): Promise<AccountPasskeySubmitOutcome> => {
    observedSubmitPrf = result.prfOutput?.slice();
    return overrides.submitOutcome ?? { status: 'locked' };
  });
  const cancel = vi.fn(async () => { attempt = undefined; return true; });
  const status = vi.fn(async () => ({ status: 'none' as const }));
  const startup = vi.fn(async () => overrides.startupStatus ?? ({ status: 'none' as const }));
  const orchestrator = new AccountPasskeyBrowserOrchestrator({
    browser,
    coordinator: { begin, resume, submit, cancel, status, startup } as never,
    attempts: { read: vi.fn(async () => attempt) } as never,
    getServerUrl: async () => SERVER,
    getAuthState: async () => overrides.authState ?? 'loggedOut',
    getPopupUrl: () => 'chrome-extension://extension-id/ui/popup/popup.html',
  });
  return {
    orchestrator,
    browser,
    connector,
    begin,
    resume,
    submit,
    cancel,
    status,
    startup,
    executeScript,
    remove,
    create,
    createWindow,
    observedSubmitPrf: () => observedSubmitPrf,
    setAttempt(value: unknown) { attempt = value; },
  };
}

async function eventually(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      assertion();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
  assertion();
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('AccountPasskeyBrowserOrchestrator', () => {
  it('opens the exact server connector and executes only in the isolated top document', async () => {
    const h = harness();

    await expect(h.orchestrator.begin()).resolves.toMatchObject({
      status: 'waiting',
      attemptId: ATTEMPT,
    });
    await eventually(() => expect(h.submit).toHaveBeenCalledOnce());

    expect(h.create).toHaveBeenCalledWith({ url: CONNECTOR_URL, active: true });
    expect(h.begin).toHaveBeenCalledWith(h.connector);
    const injection = h.executeScript.mock.calls[0]![0];
    expect(injection.world).toBe('ISOLATED');
    expect(injection.target).toEqual({ tabId: 7, documentIds: ['document-a'] });
    expect(JSON.stringify(injection.args)).not.toContain('continuation');
    await eventually(() => expect(h.createWindow).toHaveBeenCalledWith(expect.objectContaining({
      url: expect.stringContaining('accountPasskey=locked'),
      type: 'popup',
    })));
    expect(h.submit).toHaveBeenCalledWith(h.connector, ATTEMPT, {
      ...assertionResult(),
      prfOutput: new Array(32).fill(0),
    });
    expect(h.observedSubmitPrf()).toEqual(new Array(32).fill(8));
  });

  it('opens an unlocked outcome only when the coordinator confirms PRF unlock', async () => {
    const h = harness({ submitOutcome: { status: 'unlocked' } });

    await h.orchestrator.begin();

    await eventually(() => expect(h.createWindow).toHaveBeenCalledWith(expect.objectContaining({
      url: expect.stringContaining('accountPasskey=unlocked'),
      type: 'popup',
    })));
  });

  it('closes the connector and reports unavailable when the fixed endpoint cannot begin', async () => {
    const h = harness();
    h.begin.mockRejectedValueOnce(new Error('404'));

    await expect(h.orchestrator.begin()).resolves.toEqual({
      status: 'unavailable',
      reason: 'options_unavailable',
    });
    expect(h.remove).toHaveBeenCalledWith(7);
    expect(h.executeScript).not.toHaveBeenCalled();
    expect(h.createWindow).toHaveBeenCalledWith(expect.objectContaining({
      url: expect.stringContaining('accountPasskey=unavailable'),
    }));
  });

  it('fails closed before opening a tab when server-origin access is absent', async () => {
    const h = harness({ hasHostAccess: false });

    await expect(h.orchestrator.begin()).resolves.toEqual({
      status: 'unavailable',
      reason: 'host_access_unavailable',
    });
    expect(h.create).not.toHaveBeenCalled();
    expect(h.begin).not.toHaveBeenCalled();
    expect(h.executeScript).not.toHaveBeenCalled();
  });

  it('maps authenticator cancellation without submitting a token grant', async () => {
    const execute = vi.fn(async () => ([{
      frameId: 0,
      documentId: 'document-a',
      result: { kind: 'cancelled' },
    }]));
    const h = harness({ execute });

    await h.orchestrator.begin();
    await eventually(() => expect(h.cancel).toHaveBeenCalledWith(h.connector, ATTEMPT));
    expect(h.submit).not.toHaveBeenCalled();
    await eventually(() => expect(h.createWindow).toHaveBeenCalledWith(expect.objectContaining({
      url: expect.stringContaining('accountPasskey=cancelled'),
    })));
  });

  it('cancels a waiting attempt when the user closes its connector tab', async () => {
    const execution = deferred<readonly never[]>();
    const waiting = {
      status: 'waiting',
      owner: { generation: 1, attemptId: ATTEMPT, serverUrl: SERVER },
      connector: {
        tabId: 7,
        frameId: 0,
        documentId: 'document-a',
        url: CONNECTOR_URL,
        origin: 'https://vault.example',
      },
    };
    const second = harness({ execute: vi.fn(() => execution.promise), attempt: waiting });
    await second.orchestrator.begin();
    await second.orchestrator.handleTabRemoved(7);
    expect(second.cancel).toHaveBeenCalledWith(second.connector, ATTEMPT);
    expect(second.createWindow).not.toHaveBeenCalled();
    execution.resolve([]);
  });

  it('publishes the authoritative result when explicit cancellation is too late', async () => {
    const execution = deferred<readonly [{
      frameId: 0;
      documentId: string;
      result: { kind: 'success'; result: ReturnType<typeof assertionResult> };
    }]>();
    const cancellation = deferred<boolean>();
    const claimed = {
      status: 'claimed',
      owner: { generation: 1, attemptId: ATTEMPT, serverUrl: SERVER },
      connector: {
        tabId: 7,
        frameId: 0,
        documentId: 'document-a',
        url: CONNECTOR_URL,
        origin: 'https://vault.example',
      },
    };
    const h = harness({ execute: vi.fn(() => execution.promise), attempt: claimed });
    h.cancel.mockImplementationOnce(() => cancellation.promise);

    await h.orchestrator.begin();
    const cancelling = h.orchestrator.cancel();
    await eventually(() => expect(h.cancel).toHaveBeenCalledWith(h.connector, ATTEMPT));
    execution.resolve([{
      frameId: 0,
      documentId: 'document-a',
      result: { kind: 'success', result: assertionResult() },
    }]);
    await eventually(() => expect(h.submit).toHaveBeenCalledOnce());
    expect(h.createWindow).not.toHaveBeenCalled();

    cancellation.resolve(false);
    await expect(cancelling).resolves.toBe(false);
    await eventually(() => expect(h.createWindow).toHaveBeenCalledWith(expect.objectContaining({
      url: expect.stringContaining('accountPasskey=locked'),
    })));
  });

  it('publishes an unknown outcome when the connector closes after submission was claimed', async () => {
    const submission = deferred<{
      status: 'outcome_unknown';
      attemptId: string;
      terminalAt: number;
    }>();
    const claimed = {
      status: 'claimed',
      owner: { generation: 1, attemptId: ATTEMPT, serverUrl: SERVER },
      connector: {
        tabId: 7,
        frameId: 0,
        documentId: 'document-a',
        url: CONNECTOR_URL,
        origin: 'https://vault.example',
      },
    };
    const h = harness({ attempt: claimed });
    h.submit.mockImplementationOnce(() => submission.promise);
    h.cancel.mockResolvedValueOnce(false);

    await h.orchestrator.begin();
    await eventually(() => expect(h.submit).toHaveBeenCalledOnce());
    await h.orchestrator.handleTabRemoved(7);
    expect(h.createWindow).not.toHaveBeenCalled();

    submission.resolve({ status: 'outcome_unknown', attemptId: ATTEMPT, terminalAt: 2_000 });
    await eventually(() => expect(h.createWindow).toHaveBeenCalledWith(expect.objectContaining({
      url: expect.stringContaining('accountPasskey=outcome_unknown'),
    })));
  });

  it('publishes a completed result when the connector closes after the attempt was cleared', async () => {
    const submission = deferred<{ status: 'locked' }>();
    const waiting = {
      status: 'waiting',
      owner: { generation: 1, attemptId: ATTEMPT, serverUrl: SERVER },
      connector: {
        tabId: 7,
        frameId: 0,
        documentId: 'document-a',
        url: CONNECTOR_URL,
        origin: 'https://vault.example',
      },
    };
    const h = harness({ attempt: waiting });
    h.submit.mockImplementationOnce(() => submission.promise);

    await h.orchestrator.begin();
    await eventually(() => expect(h.submit).toHaveBeenCalledOnce());
    h.setAttempt(undefined);
    await h.orchestrator.handleTabRemoved(7);
    expect(h.createWindow).not.toHaveBeenCalled();

    submission.resolve({ status: 'locked' });
    await eventually(() => expect(h.createWindow).toHaveBeenCalledWith(expect.objectContaining({
      url: expect.stringContaining('accountPasskey=locked'),
    })));
  });

  it('resumes only an exact waiting connector document after worker restart', async () => {
    const execution = deferred<readonly never[]>();
    const waiting = {
      status: 'waiting',
      owner: { generation: 1, attemptId: ATTEMPT, serverUrl: SERVER },
      connector: {
        tabId: 7,
        frameId: 0,
        documentId: 'document-a',
        url: CONNECTOR_URL,
        origin: 'https://vault.example',
      },
      assertionOptions: {},
      createdAt: 1_000,
      expiresAt: Date.now() + 60_000,
    };
    const h = harness({
      attempt: waiting,
      startupStatus: { status: 'waiting', attemptId: ATTEMPT, expiresAt: waiting.expiresAt },
      execute: vi.fn(() => execution.promise),
    });

    await expect(h.orchestrator.startup()).resolves.toMatchObject({ status: 'waiting' });
    expect(h.resume).toHaveBeenCalledWith(waiting.connector);
    expect(h.begin).not.toHaveBeenCalled();
    await eventually(() => expect(h.executeScript).toHaveBeenCalledOnce());

    await expect(h.orchestrator.startup()).resolves.toMatchObject({ status: 'waiting' });
    expect(h.resume).toHaveBeenCalledTimes(1);
    expect(h.executeScript).toHaveBeenCalledTimes(1);
    execution.resolve([]);
  });

  it('turns a restored claimed attempt terminal without replaying WebAuthn or the grant', async () => {
    const claimed = {
      status: 'claimed',
      owner: { generation: 2, attemptId: ATTEMPT, serverUrl: SERVER },
      connector: {
        tabId: 7,
        frameId: 0,
        documentId: 'document-a',
        url: CONNECTOR_URL,
        origin: 'https://vault.example',
      },
    };
    const h = harness({
      attempt: claimed,
      startupStatus: { status: 'outcome_unknown', attemptId: ATTEMPT, terminalAt: 2_000 },
    });

    await expect(h.orchestrator.startup()).resolves.toMatchObject({ status: 'outcome_unknown' });
    expect(h.resume).not.toHaveBeenCalled();
    expect(h.executeScript).not.toHaveBeenCalled();
    expect(h.submit).not.toHaveBeenCalled();
    expect(h.remove).toHaveBeenCalledWith(7);
  });
});

describe('performAccountPasskeyCeremony', () => {
  it('converts WebAuthn inputs, requests PRF, and returns only the strict assertion projection', async () => {
    class FakeAssertionResponse {
      authenticatorData = new Uint8Array(37).fill(4).buffer;
      signature = new Uint8Array(64).fill(5).buffer;
      clientDataJSON = new Uint8Array(32).fill(6).buffer;
      userHandle = new Uint8Array(16).fill(7).buffer;
    }
    class FakePublicKeyCredential {
      readonly id = bytesToBase64Url(new Uint8Array(32).fill(2));
      readonly rawId = new Uint8Array(32).fill(2).buffer;
      readonly type = 'public-key';
      readonly response = new FakeAssertionResponse();
      getClientExtensionResults() {
        return { prf: { results: { first: new Uint8Array(32).fill(8).buffer } } };
      }
    }
    let observed: PublicKeyCredentialRequestOptions | undefined;
    const get = vi.fn(async (options: CredentialRequestOptions) => {
      observed = options.publicKey;
      return new FakePublicKeyCredential();
    });
    vi.stubGlobal('PublicKeyCredential', FakePublicKeyCredential);
    vi.stubGlobal('AuthenticatorAssertionResponse', FakeAssertionResponse);
    vi.stubGlobal('navigator', { credentials: { get } });

    await expect(performAccountPasskeyCeremony(ceremony())).resolves.toEqual({
      kind: 'success',
      result: assertionResult(),
    });
    expect(get).toHaveBeenCalledOnce();
    expect(observed?.rpId).toBe('vault.example');
    expect(observed?.userVerification).toBe('required');
    expect(observed?.allowCredentials?.[0]?.transports).toEqual(['internal']);
    expect((observed?.extensions as AuthenticationExtensionsClientInputs & {
      prf?: { eval?: { first?: BufferSource } };
    })?.prf?.eval?.first).toBeInstanceOf(Uint8Array);
    expect(Object.keys((await performAccountPasskeyCeremony(ceremony())) as object)).toEqual([
      'kind',
      'result',
    ]);
  });

  it('projects browser cancellation without leaking browser error details', async () => {
    vi.stubGlobal('PublicKeyCredential', class {});
    vi.stubGlobal('AuthenticatorAssertionResponse', class {});
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn(async () => { throw new DOMException('secret browser detail', 'NotAllowedError'); }),
      },
    });

    await expect(performAccountPasskeyCeremony(ceremony())).resolves.toEqual({
      kind: 'cancelled',
    });
  });

  it('rejects the authenticator all-zero PRF sentinel in the isolated ceremony', async () => {
    class FakeAssertionResponse {
      authenticatorData = new Uint8Array(37).fill(4).buffer;
      signature = new Uint8Array(64).fill(5).buffer;
      clientDataJSON = new Uint8Array(32).fill(6).buffer;
      userHandle = new Uint8Array(16).fill(7).buffer;
    }
    class FakePublicKeyCredential {
      readonly id = bytesToBase64Url(new Uint8Array(32).fill(2));
      readonly rawId = new Uint8Array(32).fill(2).buffer;
      readonly type = 'public-key';
      readonly response = new FakeAssertionResponse();
      getClientExtensionResults() {
        return { prf: { results: { first: new Uint8Array(32).buffer } } };
      }
    }
    vi.stubGlobal('PublicKeyCredential', FakePublicKeyCredential);
    vi.stubGlobal('AuthenticatorAssertionResponse', FakeAssertionResponse);
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn(async () => new FakePublicKeyCredential()) },
    });

    await expect(performAccountPasskeyCeremony(ceremony())).resolves.toEqual({ kind: 'error' });
  });
});
