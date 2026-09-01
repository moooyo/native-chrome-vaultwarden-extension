import { describe, expect, it, vi } from 'vitest';
import { WebsitePasskeyPermissionGate } from './website-passkey-permission-gate.js';

function deferred<Value>() {
  let resolve!: (value: Value) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<Value>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function makeGate(contains = vi.fn(async () => true)) {
  return {
    contains,
    gate: new WebsitePasskeyPermissionGate({ permissions: { contains } }),
  };
}

describe('WebsitePasskeyPermissionGate', () => {
  it.each([
    ['https://Example.COM:8443/login?flow=1', 'https://example.com/*'],
    ['http://localhost:43123/register', 'http://localhost/*'],
    ['http://127.0.0.1:18082/path', 'http://127.0.0.1/*'],
  ])('captures exact portless host access for %s', async (browserUrl, originPattern) => {
    const { contains, gate } = makeGate();

    const lease = await gate.capture(browserUrl);

    expect(contains).toHaveBeenCalledOnce();
    expect(contains).toHaveBeenCalledWith({ origins: [originPattern] });
    expect(lease).toEqual({ generation: 0, originPattern });
    expect(Object.isFrozen(lease)).toBe(true);
    expect(() => gate.assert(lease)).not.toThrow();
  });

  it.each([
    '',
    ' https://example.com/login',
    'https://example.com/login\n',
    'http://example.com/login',
    'https://user:password@example.com/login',
    'https://[::1]/login',
    'chrome://settings/',
  ])('rejects an ineligible browser URL without querying permissions: %j', async (browserUrl) => {
    const { contains, gate } = makeGate();

    await expect(gate.capture(browserUrl)).rejects.toMatchObject({
      code: 'denied',
      message: 'Website passkey host permission is unavailable.',
    });
    expect(contains).not.toHaveBeenCalled();
  });

  it.each([
    ['false', async () => false],
    ['non-boolean', async () => 'granted' as unknown as boolean],
    ['rejection', async () => { throw new Error('https://private.example secret'); }],
  ])('fails closed with a fixed secret-free error when contains returns %s', async (_case, check) => {
    const { gate } = makeGate(vi.fn(check));

    const error = await gate.capture('https://private.example/login').then(
      () => undefined,
      (reason: unknown) => reason,
    );

    expect(error).toMatchObject({
      code: 'denied',
      message: 'Website passkey host permission is unavailable.',
    });
    expect(JSON.stringify(error)).not.toContain('private.example');
    expect(JSON.stringify(error)).not.toContain('secret');
  });

  it('rejects capture when permission state is invalidated while contains is awaiting', async () => {
    const contains = deferred<boolean>();
    const { gate } = makeGate(vi.fn(() => contains.promise));
    const pending = gate.capture('https://example.com/login');

    gate.invalidate();
    contains.resolve(true);

    await expect(pending).rejects.toMatchObject({ code: 'denied' });
  });

  it('rejects old leases across remove/add ABA while allowing a fresh recapture', async () => {
    const { gate } = makeGate();
    const oldLease = await gate.capture('https://example.com/login');

    gate.invalidate();
    gate.invalidate();

    expect(() => gate.assert(oldLease)).toThrowError(expect.objectContaining({ code: 'denied' }));
    const freshLease = await gate.capture('https://example.com/login');
    expect(freshLease.generation).toBe(2);
    expect(() => gate.assert(freshLease)).not.toThrow();
  });

  it('rejects forged, copied, and cross-instance leases', async () => {
    const first = makeGate().gate;
    const second = makeGate().gate;
    const lease = await first.capture('https://example.com/login');

    expect(() => first.assert({ ...lease })).toThrowError(expect.objectContaining({ code: 'denied' }));
    expect(() => second.assert(lease)).toThrowError(expect.objectContaining({ code: 'denied' }));
  });
});
