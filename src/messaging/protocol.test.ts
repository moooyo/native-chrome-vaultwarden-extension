import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RequestMessage } from './protocol.js';

// Controllable browser.runtime so we can simulate an orphaned content script (extension reloaded):
// `runtime` becomes undefined, or its `.id` goes away, or sendMessage rejects mid-flight.
const runtimeRef = vi.hoisted(() => ({
  current: undefined as undefined | { id?: string; sendMessage?: (m: unknown) => Promise<unknown> },
}));

vi.mock('webextension-polyfill', () => ({
  default: { get runtime() { return runtimeRef.current; } },
}));

import { isContentTotpClipboardCode, sendRequest, isExtensionContextAlive } from './protocol.js';
import { MAX_PIN_UTF16_CODE_UNITS } from '../core/session/pin-constraints.js';

const REQ = { type: 'vault.sync' } as unknown as RequestMessage;
const RUNTIME_INCARNATION = 'a0b1c2d3-e4f5-4a6b-8c9d-0123456789ab';
const PREVIOUS_RUNTIME_INCARNATION = 'b1c2d3e4-f5a6-4b7c-8d9e-1234567890ab';
const AUTOFILL_RUNTIME_BINDING_PROPERTY = '__miyuAutofillRuntimeIncarnation';

afterEach(() => { runtimeRef.current = undefined; });

describe('sendRequest — orphaned-context resilience', () => {
  it('returns a typed error (no throw) when runtime is gone', async () => {
    runtimeRef.current = undefined;
    await expect(sendRequest(REQ)).resolves.toEqual({ ok: false, error: { code: 'error', message: 'Extension context invalidated' } });
  });

  it('returns a typed error and does not send when runtime.id is missing', async () => {
    const sendMessage = vi.fn();
    runtimeRef.current = { sendMessage };
    const res = await sendRequest(REQ);
    expect(res.ok).toBe(false);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('catches a rejected sendMessage (invalidated mid-flight)', async () => {
    runtimeRef.current = { id: 'abc', sendMessage: vi.fn().mockRejectedValue(new Error('Extension context invalidated')) };
    await expect(sendRequest(REQ)).resolves.toEqual({ ok: false, error: { code: 'error', message: 'Extension context invalidated' } });
  });

  it('passes the response through in a live context', async () => {
    const ok = { ok: true, data: null };
    const sendMessage = vi.fn().mockResolvedValue(ok);
    runtimeRef.current = { id: 'abc', sendMessage };
    await expect(sendRequest(REQ)).resolves.toEqual(ok);
    expect(sendMessage).toHaveBeenCalledWith(REQ);
  });

  it('sends an exact runtime activation command with canonical incarnation identifiers', async () => {
    const response = { ok: true, data: { status: 'active' } };
    const sendMessage = vi.fn().mockResolvedValue(response);
    runtimeRef.current = { id: 'abc', sendMessage };
    const request = {
      type: 'autofill.activateRuntime',
      runtimeIncarnation: RUNTIME_INCARNATION,
      previousRuntimeIncarnation: PREVIOUS_RUNTIME_INCARNATION,
    } satisfies RequestMessage;

    await expect(sendRequest(request)).resolves.toEqual(response);

    expect(sendMessage).toHaveBeenCalledWith(request);
    expect(Reflect.ownKeys(request)).toEqual([
      'type',
      'runtimeIncarnation',
      'previousRuntimeIncarnation',
    ]);
  });

  it('materializes a non-enumerable runtime binding as an enumerable wire field', async () => {
    const request = { type: 'autofill.getClientConfig' } satisfies RequestMessage;
    Object.defineProperty(request, AUTOFILL_RUNTIME_BINDING_PROPERTY, {
      value: RUNTIME_INCARNATION,
      enumerable: false,
      configurable: false,
      writable: false,
    });
    const sendMessage = vi.fn().mockResolvedValue({ ok: true, data: null });
    runtimeRef.current = { id: 'abc', sendMessage };

    await expect(sendRequest(request)).resolves.toEqual({ ok: true, data: null });

    expect(Object.keys(request)).toEqual(['type']);
    expect(Object.hasOwn(request, 'runtimeIncarnation')).toBe(false);
    expect(sendMessage).toHaveBeenCalledWith({
      type: 'autofill.getClientConfig',
      runtimeIncarnation: RUNTIME_INCARNATION,
    });
    const wireRequest = sendMessage.mock.calls[0]![0] as Record<string, unknown>;
    expect(Object.getOwnPropertyDescriptor(wireRequest, 'runtimeIncarnation')).toMatchObject({
      value: RUNTIME_INCARNATION,
      enumerable: true,
    });
    expect(Object.hasOwn(wireRequest, AUTOFILL_RUNTIME_BINDING_PROPERTY)).toBe(false);
  });

  it.each([
    ['uppercase', RUNTIME_INCARNATION.toUpperCase()],
    ['invalid', 'a0b1c2d3-e4f5-5a6b-8c9d-0123456789ab'],
  ])('rejects a %s hidden runtime incarnation before transport', async (_label, runtimeIncarnation) => {
    const request = { type: 'autofill.getClientConfig' } satisfies RequestMessage;
    Object.defineProperty(request, AUTOFILL_RUNTIME_BINDING_PROPERTY, {
      value: runtimeIncarnation,
      enumerable: false,
      configurable: false,
      writable: false,
    });
    const sendMessage = vi.fn();
    runtimeRef.current = { id: 'abc', sendMessage };

    await expect(sendRequest(request)).resolves.toEqual({
      ok: false,
      error: { code: 'error', message: 'Autofill runtime incarnation is invalid' },
    });
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('carries the copied value needed for an in-memory clipboard ownership claim', async () => {
    const request = { type: 'clipboard.scheduleClear', value: '123456' } satisfies RequestMessage;
    const sendMessage = vi.fn().mockResolvedValue({ ok: true, data: null });
    runtimeRef.current = { id: 'abc', sendMessage };
    await sendRequest(request);
    expect(sendMessage).toHaveBeenCalledWith(request);
  });

  it('sends an exact semantic favorite command without folder metadata', async () => {
    const request = {
      type: 'vault.setCipherFavorite',
      id: 'cipher-1',
      favorite: true,
    } satisfies RequestMessage;
    const sendMessage = vi.fn().mockResolvedValue({ ok: true, data: null });
    runtimeRef.current = { id: 'abc', sendMessage };

    await expect(sendRequest(request)).resolves.toEqual({ ok: true, data: null });

    expect(sendMessage).toHaveBeenCalledWith(request);
    expect(Reflect.ownKeys(request)).toEqual(['type', 'id', 'favorite']);
    expect(JSON.stringify(request)).not.toContain('folderId');
  });

  it('rejects widened or malformed favorite commands before transport', async () => {
    const sendMessage = vi.fn();
    runtimeRef.current = { id: 'abc', sendMessage };
    const accessor = { type: 'vault.setCipherFavorite', id: 'cipher-1' } as Record<string, unknown>;
    Object.defineProperty(accessor, 'favorite', { enumerable: true, get: () => true });

    for (const request of [
      { type: 'vault.setCipherFavorite', id: 'cipher-1', favorite: true, folderId: 'folder-1' },
      { type: 'vault.setCipherFavorite', id: ' cipher-1', favorite: true },
      { type: 'vault.setCipherFavorite', id: 'cipher-1', favorite: 1 },
      accessor,
    ]) {
      await expect(sendRequest(request as unknown as RequestMessage)).resolves.toEqual({
        ok: false,
        error: { code: 'denied', message: 'Invalid cipher favorite request.' },
      });
    }
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('carries only generated value metadata on generator history commands', async () => {
    const sendMessage = vi.fn().mockResolvedValue({ ok: true, data: { added: true } });
    runtimeRef.current = { id: 'abc', sendMessage };
    const request = {
      type: 'generator.history.track',
      entry: { value: 'generated-secret', type: 'pin', policyRevision: 7 },
    } satisfies RequestMessage;

    await sendRequest(request);

    expect(sendMessage).toHaveBeenCalledWith(request);
    expect(JSON.stringify(request)).not.toMatch(/scope|server|email|userId|crypto/u);
    const list = { type: 'generator.history.list' } satisfies RequestMessage;
    const clear = { type: 'generator.history.clear' } satisfies RequestMessage;
    expect(list.type).toBe('generator.history.list');
    expect(clear.type).toBe('generator.history.clear');
  });

  it('sends two-factor recovery as an exact destination-free command', async () => {
    const request = { type: 'auth.openTwoFactorRecovery' } satisfies RequestMessage;
    const sendMessage = vi.fn().mockResolvedValue({ ok: true, data: null });
    runtimeRef.current = { id: 'abc', sendMessage };

    await expect(sendRequest(request)).resolves.toEqual({ ok: true, data: null });
    expect(sendMessage).toHaveBeenCalledWith({ type: 'auth.openTwoFactorRecovery' });
  });

  it('sends password hints as an exact email-only command', async () => {
    const request = {
      type: 'auth.requestPasswordHint',
      email: 'User@Example.COM',
    } satisfies RequestMessage;
    const sendMessage = vi.fn().mockResolvedValue({ ok: true, data: null });
    runtimeRef.current = { id: 'abc', sendMessage };

    await expect(sendRequest(request)).resolves.toEqual({ ok: true, data: null });
    expect(sendMessage).toHaveBeenCalledWith(request);
    expect(Reflect.ownKeys(request)).toEqual(['type', 'email']);
  });

  it('rejects a widened password-hint command before transport', async () => {
    const sendMessage = vi.fn();
    runtimeRef.current = { id: 'abc', sendMessage };
    const forged = {
      type: 'auth.requestPasswordHint',
      email: 'user@example.com',
      serverUrl: 'https://evil.example',
    } as unknown as RequestMessage;

    await expect(sendRequest(forged)).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'Invalid password hint request.' },
    });
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('rejects a two-factor recovery command carrying a page-controlled URL before transport', async () => {
    const sendMessage = vi.fn();
    runtimeRef.current = { id: 'abc', sendMessage };
    const forged = {
      type: 'auth.openTwoFactorRecovery',
      url: 'https://evil.example/recover',
    } as unknown as RequestMessage;

    await expect(sendRequest(forged)).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'Invalid two-step recovery request.' },
    });
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('sends only exact SSO commands and keeps server URLs out of the protocol', async () => {
    const sendMessage = vi.fn().mockResolvedValue({ ok: true, data: { status: 'waiting' } });
    runtimeRef.current = { id: 'abc', sendMessage };
    const begin = {
      type: 'auth.sso.begin',
      email: 'user@example.com',
      organizationIdentifier: 'org-id',
    } satisfies RequestMessage;

    await sendRequest(begin);
    expect(sendMessage).toHaveBeenCalledWith(begin);
    const binding = {
      attemptId: '11111111-1111-4111-8111-111111111111',
      generation: 1,
    } as const;
    await sendRequest({ type: 'auth.sso.status', ...binding });
    await sendRequest({ type: 'auth.sso.cancel', ...binding });
    expect(sendMessage).toHaveBeenCalledWith({ type: 'auth.sso.status', ...binding });
    expect(sendMessage).toHaveBeenCalledWith({ type: 'auth.sso.cancel', ...binding });

    for (const forged of [
      { ...begin, url: 'https://evil.example/sso' },
      { type: 'auth.sso.status', state: 'stolen' },
      { type: 'auth.sso.status', attemptId: binding.attemptId },
      { type: 'auth.sso.cancel', redirectUri: 'https://evil.example/callback' },
      { type: 'auth.sso.cancel', ...binding, generation: undefined },
      { type: 'auth.sso.requirement', email: 'user@example.com', webVaultUrl: 'https://evil.example' },
    ]) {
      sendMessage.mockClear();
      await expect(sendRequest(forged as unknown as RequestMessage)).resolves.toEqual({
        ok: false,
        error: { code: 'denied', message: 'Invalid SSO request.' },
      });
      expect(sendMessage).not.toHaveBeenCalled();
    }
  });

  it.each(['auth.setPin', 'auth.unlockWithPin'] as const)(
    'rejects an oversized PIN before sending %s across the runtime protocol',
    async (type) => {
      const sendMessage = vi.fn();
      runtimeRef.current = { id: 'abc', sendMessage };
      const request = {
        type,
        pin: 'a'.repeat(MAX_PIN_UTF16_CODE_UNITS + 1),
        ...(type === 'auth.setPin' ? { requireMasterPasswordOnRestart: true } : {}),
      } as RequestMessage;

      await expect(sendRequest(request)).resolves.toMatchObject({
        ok: false,
        error: { message: expect.stringContaining('at most') },
      });
      expect(sendMessage).not.toHaveBeenCalled();
    },
  );
});

describe('isExtensionContextAlive', () => {
  it('is false with no runtime, true once runtime.id is present', () => {
    runtimeRef.current = undefined;
    expect(isExtensionContextAlive()).toBe(false);
    runtimeRef.current = { id: 'abc' };
    expect(isExtensionContextAlive()).toBe(true);
  });
});

describe('content TOTP clipboard protocol boundary', () => {
  it.each([
    '0',
    '123456',
    '12345678',
    '1234567890',
    '7W6CJ',
  ])('accepts a generator-supported code: %s', (code) => {
    expect(isContentTotpClipboardCode(code)).toBe(true);
  });

  it.each([
    '',
    '12345678901',
    ' 123456',
    '123456 ',
    '12\n3456',
    '7w6cj',
    '7W6CA',
    'secret',
    123456,
  ])('rejects a non-TOTP clipboard value: %j', (value) => {
    expect(isContentTotpClipboardCode(value)).toBe(false);
  });
});
