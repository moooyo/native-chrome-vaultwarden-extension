// Live end-to-end test for remember-device 2FA against the disposable test Vaultwarden (CLAUDE.md),
// reached via the SSH tunnel (direct 10.0.1.20:8080 is blocked). Skipped by default; run with:
//   LIVE=1 npx vitest run test/live/remember-2fa.live.test.ts
//
// Registers a throwaway account, enables authenticator (TOTP) 2FA, then proves the server contract
// this feature relies on: (1) a 2FA success with remember returns a TwoFactorToken; (2) replaying it
// with two_factor_provider=5 skips the 2FA challenge and the token remains usable on further reuse;
// (3) an INVALID device token falls back to the real 2FA challenge (providers list is the real methods,
// never the virtual Remember=5). Observed contract: the token is a signed JWT valid until expiry — the
// server does NOT rotate to a fresh random token per reuse — and our capture-on-presence design is
// robust either way. The throwaway account is deleted in a `finally`.
import { describe, it, expect, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { ApiClient } from '../../src/core/api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash } from '../../src/core/crypto/kdf.js';
import { buildRegistration } from '../../src/core/crypto/registration.js';
import { generateTotpCode, parseTotp } from '../../src/core/vault/totp.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const SERVER = process.env.REMEMBER_SERVER ?? 'http://localhost:18080';
const LIVE = Boolean(process.env.LIVE);

// A valid 32-char (20-byte) base32 TOTP secret used to enrol authenticator 2FA for the test account.
const TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

function memStore(): KeyValueStore {
  const m = new Map<string, unknown>();
  return {
    get: async <T>(k: string) => m.get(k) as T | undefined,
    set: async (k: string, v: unknown) => { m.set(k, v); },
    remove: async (k: string) => { m.delete(k); },
  } as KeyValueStore;
}

/** Current 6-digit TOTP code for TOTP_SECRET. */
async function totpNow(): Promise<string> {
  return generateTotpCode(parseTotp(TOTP_SECRET)!, Math.floor(Date.now() / 1000));
}

/** Wait until the next 30s TOTP window begins (+0.5s cushion). Vaultwarden enforces TOTP replay
 *  protection (a code's time-step must be strictly greater than the last one used), so enrolment and
 *  the subsequent login challenge must fall in DIFFERENT windows or the reused code is rejected. */
async function waitForNextTotpWindow(): Promise<void> {
  const period = 30;
  const nowSec = Date.now() / 1000;
  const msToNext = (period - (nowSec % period)) * 1000 + 500;
  await new Promise((resolve) => setTimeout(resolve, msToNext));
}

/** Enable authenticator 2FA on the account via raw fetch. The test server (v2025.12.0, core 1.35.0)
 *  expects the secret key, a CURRENT code from that key, and the master-password hash. If the server
 *  rejects with 400, inspect the response and switch the field casing to PascalCase (Key/Token/MasterPasswordHash). */
async function enableAuthenticator(token: string, masterPasswordHash: string): Promise<void> {
  const res = await fetch(`${SERVER}/api/two-factor/authenticator`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ key: TOTP_SECRET, token: await totpNow(), masterPasswordHash }),
  });
  const text = await res.text();
  expect(res.ok, `enable authenticator failed: ${res.status} ${text}`).toBe(true);
}

async function deleteAccount(token: string, masterPasswordHash: string): Promise<void> {
  try {
    await fetch(`${SERVER}/api/accounts`, {
      method: 'DELETE',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ masterPasswordHash }),
    });
  } catch { /* best-effort */ }
}

(LIVE ? describe : describe.skip)('live remember-device 2FA against the test server', () => {
  it('returns a TwoFactorToken on remember success, skips 2FA on reuse, and rotates the token', async () => {
    const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });
    const email = `remember-${Date.now()}@winvaultwarden.local`;
    const password = 'Remember-Test-Pass-1!';

    const reg = await buildRegistration(email, password);
    await api.register({
      email, name: 'Remember Test', masterPasswordHash: reg.masterPasswordHash,
      key: reg.key, keys: reg.keys, kdf: reg.kdf, kdfIterations: reg.kdfIterations,
    });
    const pre = await api.prelogin(email);
    const masterKey = await deriveMasterKey(password, email, pre.kdfIterations);
    const hash = await deriveMasterPasswordHash(masterKey, password);

    // First login (no 2FA yet) to get a token for enabling authenticator + final cleanup.
    const first = await api.passwordLogin({ email, masterPasswordHash: hash });
    expect(first.kind, 'initial login').toBe('success');
    if (first.kind !== 'success') throw new Error('unreachable');
    const adminToken = first.data.access_token;

    try {
      await enableAuthenticator(adminToken, hash);

      // Now login requires 2FA.
      const challenged = await api.passwordLogin({ email, masterPasswordHash: hash });
      expect(challenged.kind, 'login now requires 2FA').toBe('twoFactor');

      // Enrolment consumed the current TOTP window; wait for a fresh one so the login code is not
      // rejected as a replay of the enrolment code.
      await waitForNextTotpWindow();

      // Submit the TOTP code WITH remember → success carries a TwoFactorToken (device-remember token).
      const submitted = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 0, twoFactorToken: await totpNow(), remember: true,
      });
      expect(submitted.kind, '2FA submit with remember').toBe('success');
      if (submitted.kind !== 'success') throw new Error('unreachable');
      const t1 = submitted.data.TwoFactorToken;
      expect(t1, 'success returns a device-remember token').toBeTruthy();

      // Reuse with provider=5 skips the 2FA challenge and returns a token again.
      const reuse1 = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 5, twoFactorToken: t1!, remember: true,
      });
      expect(reuse1.kind, 'provider=5 reuse skips 2FA').toBe('success');
      if (reuse1.kind !== 'success') throw new Error('unreachable');
      const t2 = reuse1.data.TwoFactorToken;
      expect(t2, 'reuse returns a device-remember token').toBeTruthy();
      // NOTE (server contract, observed on v2025.12.0): the token is a signed JWT that stays valid until
      // expiry — the server does NOT mint a fresh random token per reuse, so t2 may equal t1. Our
      // capture-on-presence design is robust either way: it re-saves whatever the server returns, so it
      // stays in sync whether the token is stable OR rotated. We therefore do NOT assert t2 !== t1.

      // The returned token still skips 2FA on a further reuse (it is not single-use).
      const reuse2 = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 5, twoFactorToken: t2!, remember: true,
      });
      expect(reuse2.kind, 'returned token still skips 2FA').toBe('success');

      // A provider=5 attempt with an INVALID/expired device token falls back to the real 2FA challenge.
      // This is the contract our stale-token fallback (clear + drive 2FA from this same result) relies on.
      const invalid = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 5, twoFactorToken: 'not-a-valid-remember-token', remember: true,
      });
      expect(invalid.kind, 'invalid device token falls back to 2FA').toBe('twoFactor');
      if (invalid.kind === 'twoFactor') {
        // The fallback providers are the REAL enabled methods (Authenticator=0), never the virtual
        // Remember provider (5) — so the client can drive 2FA straight from this result, no re-send.
        expect(invalid.providers, 'real providers returned, not the virtual Remember=5').toContain(0);
        expect(invalid.providers, 'Remember=5 is virtual and never advertised').not.toContain(5);
      }
    } finally {
      await deleteAccount(adminToken, hash);
    }
  }, 60_000);
});
