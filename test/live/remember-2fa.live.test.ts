// Live end-to-end test for remember-device 2FA against a disposable test Vaultwarden (MIYU_SERVER / MIYU_EMAIL / MIYU_PASSWORD),
// reached via the SSH tunnel (direct localhost:8080 is blocked). Excluded by default; run with:
//   $env:LIVE = '1'; npm run test:live -- test/live/remember-2fa.live.test.ts
//
// Registers a throwaway account, enables authenticator (TOTP) 2FA, then proves the server contract
// this feature relies on: (1) a 2FA success with remember returns a TwoFactorToken; (2) replaying it
// with two_factor_provider=5 skips the 2FA challenge and the token remains usable on further reuse;
// (3) an INVALID device token falls back to the real 2FA challenge (providers list is the real methods,
// never the virtual Remember=5). Observed contract: the token is a signed JWT valid until expiry — the
// server may omit a replacement token on reuse, and our capture-on-presence design preserves the
// still-valid original token. The throwaway account is deleted in a `finally`.
import { describe, it, expect, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { ApiClient, BITWARDEN_CLIENT_VERSION } from '../../src/core/api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash } from '../../src/core/crypto/kdf.js';
import { buildRegistration } from '../../src/core/crypto/registration.js';
import { generateTotpCode, parseTotp } from '../../src/core/vault/totp.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const SERVER = process.env.REMEMBER_SERVER ?? 'http://localhost:18080';
const LIVE = process.env.LIVE === '1';
const PRESEEDED = process.env.MIYU_TOTP_PRESEEDED === '1';
const PRESEEDED_EMAIL = process.env.MIYU_EMAIL;
const PRESEEDED_PASSWORD = process.env.MIYU_PASSWORD;

if (LIVE && PRESEEDED && (!PRESEEDED_EMAIL || !PRESEEDED_PASSWORD)) {
  throw new Error('MIYU_EMAIL and MIYU_PASSWORD are required for a pre-seeded TOTP fixture');
}

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

/** Current 6-digit TOTP code for the provided Base32 secret. */
async function totpNow(secret: string): Promise<string> {
  return generateTotpCode(parseTotp(secret)!, Math.floor(Date.now() / 1000));
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

function hasAsciiControlOrSpace(value: string): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0);
    return code <= 0x20 || code === 0x7f;
  });
}

async function requestRegistrationToken(email: string): Promise<string | undefined> {
  const response = await fetch(`${SERVER}/identity/accounts/register/send-verification-email`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ email, name: 'Remember Test' }),
  });
  if (response.status === 404) return undefined;
  if (response.status === 204) {
    throw new Error('test server requires email verification; no inline registration token is available');
  }
  if (!response.ok) throw new Error(`registration start failed with status ${response.status}`);
  const text = (await response.text()).trim();
  if (!text) throw new Error('registration start returned an empty token');
  let token: unknown = text;
  try {
    token = JSON.parse(text) as unknown;
  } catch {
    // Current servers return raw opaque text; older compatible builds used JSON text.
  }
  if (typeof token !== 'string' || !token || token.length > 16_384 || hasAsciiControlOrSpace(token)) {
    throw new Error('registration start returned an invalid token');
  }
  return token;
}

/** Enable authenticator 2FA through the current user-verification-token handshake. */
async function enableAuthenticator(token: string, masterPasswordHash: string): Promise<string> {
  const verification = await fetch(`${SERVER}/api/two-factor/get-authenticator`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ masterPasswordHash }),
  });
  const verificationText = await verification.text();
  expect(
    verification.ok,
    `get authenticator verification failed: ${verification.status} ${verificationText}`,
  ).toBe(true);
  const verificationBody = JSON.parse(verificationText) as unknown;
  if (typeof verificationBody !== 'object' || verificationBody === null) {
    throw new Error('get authenticator returned an invalid response');
  }
  const record = verificationBody as Record<string, unknown>;
  const authenticatorValue = record.authenticator ?? record.Authenticator;
  if (typeof authenticatorValue !== 'object' || authenticatorValue === null) {
    throw new Error('get authenticator omitted the authenticator details');
  }
  const authenticator = authenticatorValue as Record<string, unknown>;
  const key = authenticator.key ?? authenticator.Key;
  if (typeof key !== 'string' || !parseTotp(key)) {
    throw new Error('get authenticator returned an invalid TOTP key');
  }
  const userVerificationToken = record.userVerificationToken ?? record.UserVerificationToken;
  if (typeof userVerificationToken !== 'string' || !userVerificationToken) {
    throw new Error('get authenticator omitted the user verification token');
  }

  const res = await fetch(`${SERVER}/api/two-factor/authenticator`, {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ key, token: await totpNow(key), userVerificationToken }),
  });
  const text = await res.text();
  expect(res.ok, `enable authenticator failed: ${res.status} ${text}`).toBe(true);
  return key;
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
  it('returns a TwoFactorToken on remember success and keeps it usable across reuse', async () => {
    const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });
    const email = PRESEEDED ? PRESEEDED_EMAIL! : `remember-${Date.now()}@example.com`;
    const password = PRESEEDED ? PRESEEDED_PASSWORD! : 'Remember-Test-Pass-1!';
    let adminToken: string | undefined;
    let cleanupToken: string | undefined;
    let totpSecret = TOTP_SECRET;

    if (!PRESEEDED) {
      const reg = await buildRegistration(email, password);
      const emailVerificationToken = await requestRegistrationToken(email);
      await api.register({
        ...reg,
        masterPasswordHint: '',
        email,
        name: 'Remember Test',
        ...(emailVerificationToken ? { emailVerificationToken } : {}),
      });
    }
    const pre = await api.prelogin(email);
    const masterKey = await deriveMasterKey(password, email, pre);
    const hash = await deriveMasterPasswordHash(masterKey, password);
    masterKey.fill(0);

    try {
      if (!PRESEEDED) {
        // The 2026.8 API restricts provider management to web-client tokens. Test environments may
        // instead set MIYU_TOTP_PRESEEDED=1 and seed the documented provider record directly.
        const first = await api.passwordLogin({ email, masterPasswordHash: hash });
        expect(first.kind, 'initial login').toBe('success');
        if (first.kind !== 'success') throw new Error('unreachable');
        adminToken = first.data.access_token;
        totpSecret = await enableAuthenticator(adminToken, hash);
      }

      // Now login requires 2FA.
      const challenged = await api.passwordLogin({ email, masterPasswordHash: hash });
      expect(challenged.kind, 'login now requires 2FA').toBe('twoFactor');

      // Enrolment consumed the current TOTP window; wait for a fresh one so the login code is not
      // rejected as a replay of the enrolment code.
      if (!PRESEEDED) await waitForNextTotpWindow();

      // Submit the TOTP code WITH remember → success carries a TwoFactorToken (device-remember token).
      const submitted = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 0, twoFactorToken: await totpNow(totpSecret), remember: true,
      });
      expect(submitted.kind, '2FA submit with remember').toBe('success');
      if (submitted.kind !== 'success') throw new Error('unreachable');
      cleanupToken = submitted.data.access_token;
      const t1 = submitted.data.TwoFactorToken;
      expect(t1, 'success returns a device-remember token').toBeTruthy();

      // Reuse with provider=5 skips the 2FA challenge. Modern servers may omit a replacement token.
      const reuse1 = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 5, twoFactorToken: t1!, remember: true,
      });
      expect(reuse1.kind, 'provider=5 reuse skips 2FA').toBe('success');
      if (reuse1.kind !== 'success') throw new Error('unreachable');
      const reusableToken = reuse1.data.TwoFactorToken ?? t1!;

      // The original or replacement token still skips 2FA on a further reuse (it is not single-use).
      const reuse2 = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 5, twoFactorToken: reusableToken, remember: true,
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
      const token = cleanupToken ?? adminToken;
      if (token) await deleteAccount(token, hash);
    }
  }, 60_000);
});
