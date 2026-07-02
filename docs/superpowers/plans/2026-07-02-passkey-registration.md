# Passkey Registration + Trust-Boundary Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a site's `navigator.credentials.create()` store a new ES256 passkey in the vault (new login item OR appended to a same-domain personal login) and return a valid WebAuthn attestation, and — prompted by adversarial review — move the passkey rpId/origin trust boundary into the worker (PSL-backed) so the delivered assertion path is no longer cross-origin-forgeable.

**Architecture:** Mirror the delivered assertion path: MAIN-world `page-webauthn.ts` wraps `create`, the isolated-world `webauthn-bridge.ts` relays (candidate query + closed-shadow-root picker for consent, stamping `origin` from its own `location`), and the worker generates the keypair, builds the attestationObject (COSE key + attested authData + `fmt:none`), encrypts a `Fido2CredentialData`, stores it, merges the returned cipher into the cache, and returns the attestation. A shared `isRegistrableRpId` (tldts/PSL) validates rpId↔origin in the worker for both get and create.

**Tech Stack:** TypeScript, MV3 extension (service worker + content scripts), WebCrypto (ECDSA P-256), a minimal hand-rolled CBOR encoder, `tldts` (already a dep), Vitest, esbuild.

## Global Constraints

- **Trust boundary is the worker.** The isolated-world bridge stamps `origin = location.origin` and gates `isSecureContext`; the worker validates `isRegistrableRpId(rpId, new URL(origin).hostname)` on EVERY passkey op (get + create) and uses the stamped origin for signing/attestation. Never trust page-supplied `origin`. Never use page-supplied rpId without this PSL check.
- **`isRegistrableRpId(rpId, host)`**: `host===rpId || host.endsWith('.'+rpId)`, AND rpId is a registrable domain (tldts `getDomain(rpId,{allowPrivateDomains:true})` non-null and equal to that of host), rejecting bare public suffixes (`github.io`, `co.uk`); `localhost` allowed only for an exact `localhost` match.
- **Attestation:** ES256 (`alg -7`) P-256 only; `fmt:"none"`, empty `attStmt`; AAGUID all-zero; `credentialIdLength` uint16 **big-endian**; signCount 0; **authData flags = UP(0x01)|AT(0x40)|BE(0x08)|BS(0x10)|(UV?0x04:0)** (`0x5D` with UV, `0x59` without) — synced discoverable passkeys are backup-eligible+backed-up. The delivered **assertion** authData must carry matching BE|BS (WebAuthn L3 §6.1.3 invariance).
- **CBOR map keys in canonical order:** COSE `{1,3,-1,-2,-3}`; attestationObject `{fmt, attStmt, authData}`.
- **Append safety:** append targets are WRITABLE PERSONAL logins only (no org-owned); the new `Fido2CredentialData` is encrypted under `cipherFieldKey(original)`; the PUT is built from the ORIGINAL `CipherResponse` verbatim with `login.fido2Credentials = [...original (verbatim EncStrings), newCred]` — it does NOT go through `updateCipher(id,input)`/`encryptCipher`/`mergeServerManagedFields` (those would drop the new passkey). `targetCipherId` is re-resolved in the worker through the same domain match (never trust a caller-supplied id).
- **Atomicity:** after a successful POST/PUT, MERGE the returned `CipherResponse` into `VAULT_CACHE_KEY.ciphers` (best-effort); do NOT run a separate `sync()` that could throw after the server write. A successful server write always returns the attestation.
- **Secrets:** the generated private key never leaves the worker (attestationObject/publicKeySpki carry only the public key); candidate targets carry only `{id,name,username}`; consent via closed shadow root + `isTrusted`.
- **Fallback to native** (`page-webauthn` returns `originalCreate(options)`): no `publicKey`; insecure context; rpId not a registrable suffix of host; no `alg -7`; `authenticatorAttachment==='cross-platform'`; excludeCredentials matches a stored passkey (best-effort dup-avoidance); `options.signal` aborted; vault locked / worker rejects rpId; user cancels; any error.
- Argon2 out of scope; do not touch reprompt / URI-match / other worker guards. TDD, DRY, YAGNI, frequent commits.

---

### Task 1: `isRegistrableRpId` (PSL-backed) in domain.ts

**Files:**
- Modify: `src/core/vault/domain.ts`
- Test: `src/core/vault/domain.test.ts` (create if absent)

**Interfaces:**
- Consumes: `tldts` `getDomain` (already imported in domain.ts).
- Produces: `export function isRegistrableRpId(rpId: string, host: string): boolean`.

- [ ] **Step 1: Write the failing tests**

Create/append `src/core/vault/domain.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { isRegistrableRpId } from './domain.js';

describe('isRegistrableRpId', () => {
  it('accepts exact and subdomain matches on a registrable domain', () => {
    expect(isRegistrableRpId('example.com', 'example.com')).toBe(true);
    expect(isRegistrableRpId('example.com', 'app.example.com')).toBe(true);
    expect(isRegistrableRpId('example.co.uk', 'app.example.co.uk')).toBe(true);
  });
  it('rejects a bare public suffix as rpId (no PSL registrable domain)', () => {
    expect(isRegistrableRpId('github.io', 'a.github.io')).toBe(false);
    expect(isRegistrableRpId('co.uk', 'foo.co.uk')).toBe(false);
  });
  it('rejects a cross-domain rpId', () => {
    expect(isRegistrableRpId('evil.com', 'victim.com')).toBe(false);
    expect(isRegistrableRpId('example.com', 'notexample.com')).toBe(false); // not a dot-suffix
  });
  it('rejects an IP rpId and allows only exact localhost', () => {
    expect(isRegistrableRpId('1.2.3.4', '1.2.3.4')).toBe(false);
    expect(isRegistrableRpId('localhost', 'localhost')).toBe(true);
    expect(isRegistrableRpId('localhost', 'app.localhost')).toBe(false);
  });
  it('is case-insensitive and rejects empty', () => {
    expect(isRegistrableRpId('Example.com', 'APP.EXAMPLE.COM')).toBe(true);
    expect(isRegistrableRpId('', 'example.com')).toBe(false);
  });
});
```

- [ ] **Step 2: Run to verify fail**

Run: `npx vitest run src/core/vault/domain.test.ts`
Expected: FAIL — `isRegistrableRpId is not a function`.

- [ ] **Step 3: Implement**

In `src/core/vault/domain.ts`, add (the file already `import { getDomain } from 'tldts'`):

```ts
/**
 * WebAuthn rpId validity: rpId must equal the frame host or be a registrable-domain suffix of it,
 * and must itself be a registrable domain (never a bare public suffix like github.io / co.uk). Uses
 * the Public Suffix List via tldts. `localhost` is allowed only for an exact localhost match (dev).
 */
export function isRegistrableRpId(rpId: string, host: string): boolean {
  const r = rpId.trim().toLowerCase();
  const h = host.trim().toLowerCase();
  if (!r || !h) return false;
  if (r === 'localhost') return h === 'localhost';
  if (h !== r && !h.endsWith(`.${r}`)) return false;
  const rBase = getDomain(r, { allowPrivateDomains: true });
  const hBase = getDomain(h, { allowPrivateDomains: true });
  if (!rBase || !hBase) return false; // public suffix, IP, or invalid
  return rBase.toLowerCase() === hBase.toLowerCase();
}
```

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run src/core/vault/domain.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/vault/domain.ts src/core/vault/domain.test.ts
git commit -m "feat: isRegistrableRpId (PSL-backed rpId<->host validity) in domain"
```

---

### Task 2: Minimal CBOR encoder (`cbor.ts`)

**Files:**
- Create: `src/core/crypto/cbor.ts`
- Test: `src/core/crypto/cbor.test.ts`

**Interfaces:**
- Consumes: `utf8ToBytes` from `../crypto/encoding.js`.
- Produces: `cborUint(n)`, `cborNegInt(n)`, `cborBytes(b)`, `cborText(s)`, `cborMap(pairs)` — each returns `number[]`; plus `cborDecode(bytes)` (test/verify helper) returning a JS value where byte-strings become `Uint8Array` and map keys stay as JS numbers/strings.

- [ ] **Step 1: Write the failing tests**

Create `src/core/crypto/cbor.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { cborUint, cborNegInt, cborBytes, cborText, cborMap, cborDecode } from './cbor.js';

describe('cbor encoder', () => {
  it('encodes unsigned ints across size boundaries', () => {
    expect(cborUint(0)).toEqual([0x00]);
    expect(cborUint(23)).toEqual([0x17]);
    expect(cborUint(24)).toEqual([0x18, 24]);
    expect(cborUint(255)).toEqual([0x18, 255]);
    expect(cborUint(256)).toEqual([0x19, 0x01, 0x00]);
    expect(cborUint(65536)).toEqual([0x1a, 0x00, 0x01, 0x00, 0x00]);
  });
  it('encodes negative COSE keys -1,-2,-3', () => {
    expect(cborNegInt(-1)).toEqual([0x20]);
    expect(cborNegInt(-2)).toEqual([0x21]);
    expect(cborNegInt(-3)).toEqual([0x22]);
    expect(cborNegInt(-7)).toEqual([0x26]);
  });
  it('encodes byte and text strings with length prefix', () => {
    expect(cborBytes(new Uint8Array([1, 2, 3]))).toEqual([0x43, 1, 2, 3]);
    expect(cborText('fmt')).toEqual([0x63, 0x66, 0x6d, 0x74]);
    expect(cborText('none')).toEqual([0x64, 0x6e, 0x6f, 0x6e, 0x65]);
  });
  it('encodes an empty map and a small map', () => {
    expect(cborMap([])).toEqual([0xa0]);
    expect(cborMap([[...cborText('fmt'), ...cborText('none')]])).toEqual([0xa1, 0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65]);
  });
  it('round-trips a COSE-shaped map through the decoder', () => {
    const x = new Uint8Array(32).fill(7);
    const y = new Uint8Array(32).fill(9);
    const cose = new Uint8Array(cborMap([
      [...cborUint(1), ...cborUint(2)],
      [...cborUint(3), ...cborNegInt(-7)],
      [...cborNegInt(-1), ...cborUint(1)],
      [...cborNegInt(-2), ...cborBytes(x)],
      [...cborNegInt(-3), ...cborBytes(y)],
    ]));
    const decoded = cborDecode(cose) as Map<number, unknown>;
    expect(decoded.get(1)).toBe(2);
    expect(decoded.get(3)).toBe(-7);
    expect(decoded.get(-1)).toBe(1);
    expect(decoded.get(-2)).toEqual(x);
    expect(decoded.get(-3)).toEqual(y);
  });
  it('decodes fmt/attStmt/authData attestation map', () => {
    const authData = new Uint8Array([0xaa, 0xbb]);
    const att = new Uint8Array(cborMap([
      [...cborText('fmt'), ...cborText('none')],
      [...cborText('attStmt'), ...cborMap([])],
      [...cborText('authData'), ...cborBytes(authData)],
    ]));
    const decoded = cborDecode(att) as Map<string, unknown>;
    expect(decoded.get('fmt')).toBe('none');
    expect(decoded.get('attStmt')).toBeInstanceOf(Map);
    expect(decoded.get('authData')).toEqual(authData);
  });
});
```

- [ ] **Step 2: Run to verify fail**

Run: `npx vitest run src/core/crypto/cbor.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

Create `src/core/crypto/cbor.ts`:

```ts
// Minimal CBOR (RFC 8949) encoder — only the shapes WebAuthn attestation needs: unsigned ints,
// negative ints, byte strings, text strings, and definite-length maps. Plus a small decoder used
// by tests/self-verification. NOT a general-purpose CBOR library.
import { utf8ToBytes } from './encoding.js';

function head(major: number, value: number): number[] {
  const mt = major << 5;
  if (value < 24) return [mt | value];
  if (value < 0x100) return [mt | 24, value];
  if (value < 0x10000) return [mt | 25, (value >> 8) & 0xff, value & 0xff];
  return [mt | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
}

export function cborUint(n: number): number[] { return head(0, n); }
/** CBOR negative integer. `n` is the negative value itself (e.g. -7); encoded arg is (-1 - n). */
export function cborNegInt(n: number): number[] { return head(1, -1 - n); }
export function cborBytes(b: Uint8Array): number[] { return [...head(2, b.length), ...b]; }
export function cborText(s: string): number[] { const b = utf8ToBytes(s); return [...head(3, b.length), ...b]; }
/** Definite-length map. `pairs` are already-encoded [..key, ..value] byte arrays; caller supplies
 *  keys in canonical order. */
export function cborMap(pairs: number[][]): number[] {
  const out = head(5, pairs.length);
  for (const p of pairs) out.push(...p);
  return out;
}

/** Minimal decoder for the subset we encode. Byte strings → Uint8Array; maps → Map. Test/verify only. */
export function cborDecode(bytes: Uint8Array): unknown {
  let i = 0;
  function readArg(ai: number): number {
    if (ai < 24) return ai;
    if (ai === 24) return bytes[i++]!;
    if (ai === 25) { const v = (bytes[i]! << 8) | bytes[i + 1]!; i += 2; return v; }
    if (ai === 26) { const v = ((bytes[i]! << 24) | (bytes[i + 1]! << 16) | (bytes[i + 2]! << 8) | bytes[i + 3]!) >>> 0; i += 4; return v; }
    throw new Error('unsupported cbor arg');
  }
  function read(): unknown {
    const b = bytes[i++]!;
    const major = b >> 5;
    const ai = b & 0x1f;
    if (major === 0) return readArg(ai);
    if (major === 1) return -1 - readArg(ai);
    if (major === 2) { const len = readArg(ai); const v = bytes.slice(i, i + len); i += len; return v; }
    if (major === 3) { const len = readArg(ai); const v = new TextDecoder().decode(bytes.slice(i, i + len)); i += len; return v; }
    if (major === 5) { const n = readArg(ai); const m = new Map<unknown, unknown>(); for (let k = 0; k < n; k++) { const key = read(); m.set(key, read()); } return m; }
    throw new Error('unsupported cbor major type ' + major);
  }
  return read();
}
```

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run src/core/crypto/cbor.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/crypto/cbor.ts src/core/crypto/cbor.test.ts
git commit -m "feat: minimal CBOR encoder + test decoder for WebAuthn attestation"
```

---

### Task 3: Attestation crypto (`fido2-create.ts`) + BE/BS on assertion (`fido2.ts`)

**Files:**
- Create: `src/core/vault/fido2-create.ts`
- Modify: `src/core/vault/fido2.ts` (add BE/BS to `buildAuthenticatorData` flags)
- Test: `src/core/vault/fido2-create.test.ts`
- Test: `src/core/vault/fido2.test.ts` (add a BE/BS flags assertion)

**Interfaces:**
- Consumes: `cborUint/cborNegInt/cborBytes/cborText/cborMap` (Task 2); `utf8ToBytes`, `bytesToBase64Url` from `../crypto/encoding.js`; `signFido2Assertion`, `derToRawSignature` from `./fido2.js`; `encryptToText` from `../crypto/encstring.js`; `Fido2CredentialData` from `../api/types.js`.
- Produces:
  - `generateFido2Keypair(): Promise<{ pkcs8: Uint8Array; coseKey: Uint8Array; credentialId: Uint8Array; publicKeySpki: Uint8Array }>`
  - `buildAttestationObject(params: { rpId: string; coseKey: Uint8Array; credentialId: Uint8Array; userVerified: boolean }): Promise<{ attestationObject: Uint8Array; authData: Uint8Array }>`
  - `buildCreateClientDataJSON(challenge: string, origin: string): string`
  - `encryptFido2Credential(cred: NewFido2Credential, key: SymmetricKey): Promise<Fido2CredentialData>` where `NewFido2Credential = { credentialId: string; keyValue: string; rpId: string; counter: number; userHandle?: string; userName?: string; rpName?: string; userDisplayName?: string }`

- [ ] **Step 1: Write the failing tests**

Create `src/core/vault/fido2-create.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { generateFido2Keypair, buildAttestationObject, buildCreateClientDataJSON } from './fido2-create.js';
import { cborDecode } from '../crypto/cbor.js';
import { signFido2Assertion, derToRawSignature } from './fido2.js';
import { base64UrlToBytes } from '../crypto/encoding.js';

const subtle = globalThis.crypto.subtle;

describe('fido2-create', () => {
  it('generates a P-256 keypair with a 16-byte credentialId and SPKI public key', async () => {
    const kp = await generateFido2Keypair();
    expect(kp.credentialId.length).toBe(16);
    expect(kp.pkcs8.length).toBeGreaterThan(0);
    // SPKI imports as an ECDSA P-256 public key.
    await expect(subtle.importKey('spki', kp.publicKeySpki as BufferSource, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])).resolves.toBeTruthy();
  });

  it('builds attestation authData with flags 0x5D (UP|AT|BE|BS|UV) and a decodable COSE key', async () => {
    const kp = await generateFido2Keypair();
    const { attestationObject, authData } = await buildAttestationObject({ rpId: 'example.com', coseKey: kp.coseKey, credentialId: kp.credentialId, userVerified: true });
    // authData: rpIdHash(32) | flags(1) | signCount(4) | AAGUID(16) | credIdLen(2 BE) | credId | COSE
    expect(authData[32]).toBe(0x5d);
    expect([authData[33], authData[34], authData[35], authData[36]]).toEqual([0, 0, 0, 0]); // signCount 0
    expect(Array.from(authData.slice(37, 53))).toEqual(new Array(16).fill(0)); // AAGUID all-zero
    const credIdLen = (authData[53]! << 8) | authData[54]!;
    expect(credIdLen).toBe(16);
    expect(Array.from(authData.slice(55, 71))).toEqual(Array.from(kp.credentialId));
    // attestationObject decodes to {fmt:'none', attStmt:{}, authData}
    const att = cborDecode(attestationObject) as Map<string, unknown>;
    expect(att.get('fmt')).toBe('none');
    expect(att.get('attStmt')).toBeInstanceOf(Map);
    expect((att.get('attStmt') as Map<unknown, unknown>).size).toBe(0);
    expect(att.get('authData')).toEqual(authData);
    // COSE key inside authData decodes with the right params.
    const cose = cborDecode(authData.slice(71)) as Map<number, unknown>;
    expect(cose.get(1)).toBe(2); expect(cose.get(3)).toBe(-7); expect(cose.get(-1)).toBe(1);
    expect((cose.get(-2) as Uint8Array).length).toBe(32);
    expect((cose.get(-3) as Uint8Array).length).toBe(32);
  });

  it('sets flags 0x59 when userVerified is false', async () => {
    const kp = await generateFido2Keypair();
    const { authData } = await buildAttestationObject({ rpId: 'example.com', coseKey: kp.coseKey, credentialId: kp.credentialId, userVerified: false });
    expect(authData[32]).toBe(0x59);
  });

  it('KEYPAIR ROUND-TRIP: an assertion signed with the generated private key verifies under the attested public key', async () => {
    const kp = await generateFido2Keypair();
    const { authData } = await buildAttestationObject({ rpId: 'example.com', coseKey: kp.coseKey, credentialId: kp.credentialId, userVerified: true });
    // Recover the public key from the COSE key embedded in authData.
    const cose = cborDecode(authData.slice(71)) as Map<number, unknown>;
    const x = cose.get(-2) as Uint8Array, y = cose.get(-3) as Uint8Array;
    const rawPub = new Uint8Array([0x04, ...x, ...y]);
    const pubKey = await subtle.importKey('raw', rawPub as BufferSource, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    // Sign an assertion with the stored private key (the same keyValue path production stores).
    const assertion = await signFido2Assertion(kp.pkcs8, { rpId: 'example.com', origin: 'https://example.com', challenge: 'AAAA' });
    const signedData = new Uint8Array([
      ...base64UrlToBytes(assertion.authenticatorData),
      ...new Uint8Array(await subtle.digest('SHA-256', base64UrlToBytes(assertion.clientDataJSON) as BufferSource)),
    ]);
    const rawSig = derToRawSignature(base64UrlToBytes(assertion.signature));
    expect(await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, rawSig as BufferSource, signedData as BufferSource)).toBe(true);
  });

  it('clientDataJSON has type webauthn.create and passes challenge/origin through', () => {
    const json = JSON.parse(buildCreateClientDataJSON('Y2hhbA', 'https://example.com'));
    expect(json).toEqual({ type: 'webauthn.create', challenge: 'Y2hhbA', origin: 'https://example.com', crossOrigin: false });
  });
});
```

Also append to `src/core/vault/fido2.test.ts` a flags check (find the existing assertion-building test to see the helper; add):

```ts
it('assertion authData carries BE|BS (and UP), UV only when requested', async () => {
  const up = await buildAuthenticatorData('example.com', 0x01 | 0x08 | 0x10, 0);
  expect(up[32]).toBe(0x19); // UP|BE|BS, no UV
});
```

- [ ] **Step 2: Run to verify fail**

Run: `npx vitest run src/core/vault/fido2-create.test.ts src/core/vault/fido2.test.ts`
Expected: FAIL — `fido2-create` not found; the fido2 flags test passes already since `buildAuthenticatorData` takes explicit flags (this test just documents the bit values).

- [ ] **Step 3: Add BE/BS to fido2.ts assertion flags**

In `src/core/vault/fido2.ts`, extend the flag constants (currently lines 31-32) and the assertion flags in `signFido2Assertion` (line 59):

```ts
// Authenticator data flags (WebAuthn §6.1): UP=user present, UV=user verified, BE=backup eligible,
// BS=backup state. Vault passkeys are synced (cloud-backed) → BE and BS are set on every ceremony.
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
```

Change line 59 from `const flags = FLAG_UP | (params.userVerified ? FLAG_UV : 0);` to:

```ts
    const flags = FLAG_UP | FLAG_BE | FLAG_BS | (params.userVerified ? FLAG_UV : 0);
```

- [ ] **Step 4: Implement fido2-create.ts**

Create `src/core/vault/fido2-create.ts`:

```ts
// FIDO2 / WebAuthn REGISTRATION (navigator.credentials.create) for vault-stored passkeys. Generates an
// ES256 (P-256) keypair in the worker, builds the attestationObject (COSE public key + attested
// authenticator data, fmt="none"), and encrypts the credential for storage. The private key never
// leaves the worker; only the public attestation is returned to the page.
import { bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';
import { cborBytes, cborMap, cborNegInt, cborText, cborUint } from '../crypto/cbor.js';
import { encryptToText } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import type { Fido2CredentialData } from '../api/types.js';

const subtle = globalThis.crypto.subtle;
const FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_BE = 0x08, FLAG_BS = 0x10, FLAG_AT = 0x40;

export interface GeneratedFido2Keypair {
  pkcs8: Uint8Array;        // private key (PKCS#8) — stays in the worker
  coseKey: Uint8Array;      // public key as a COSE_Key (CBOR)
  credentialId: Uint8Array; // 16 random bytes
  publicKeySpki: Uint8Array; // public key as SPKI DER (for the page's getPublicKey())
}

export async function generateFido2Keypair(): Promise<GeneratedFido2Keypair> {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
  const raw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey)); // 0x04 || x(32) || y(32)
  const x = raw.slice(1, 33), y = raw.slice(33, 65);
  const coseKey = new Uint8Array(cborMap([
    [...cborUint(1), ...cborUint(2)],     // kty: EC2
    [...cborUint(3), ...cborNegInt(-7)],  // alg: ES256
    [...cborNegInt(-1), ...cborUint(1)],  // crv: P-256
    [...cborNegInt(-2), ...cborBytes(x)], // x
    [...cborNegInt(-3), ...cborBytes(y)], // y
  ]));
  const publicKeySpki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));
  const credentialId = crypto.getRandomValues(new Uint8Array(16));
  return { pkcs8, coseKey, credentialId, publicKeySpki };
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', data as BufferSource));
}

export async function buildAttestationObject(params: {
  rpId: string; coseKey: Uint8Array; credentialId: Uint8Array; userVerified: boolean;
}): Promise<{ attestationObject: Uint8Array; authData: Uint8Array }> {
  const rpIdHash = await sha256(utf8ToBytes(params.rpId));
  const flags = FLAG_UP | FLAG_AT | FLAG_BE | FLAG_BS | (params.userVerified ? FLAG_UV : 0);
  const credLen = params.credentialId.length;
  const attestedCredData = new Uint8Array([
    ...new Uint8Array(16),                 // AAGUID (all zero)
    (credLen >> 8) & 0xff, credLen & 0xff, // credentialIdLength, uint16 big-endian
    ...params.credentialId,
    ...params.coseKey,
  ]);
  const authData = new Uint8Array([...rpIdHash, flags, 0, 0, 0, 0, ...attestedCredData]);
  const attestationObject = new Uint8Array(cborMap([
    [...cborText('fmt'), ...cborText('none')],
    [...cborText('attStmt'), ...cborMap([])],
    [...cborText('authData'), ...cborBytes(authData)],
  ]));
  return { attestationObject, authData };
}

export function buildCreateClientDataJSON(challenge: string, origin: string): string {
  return JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false });
}

export interface NewFido2Credential {
  credentialId: string; keyValue: string; rpId: string; counter: number;
  userHandle?: string; userName?: string; rpName?: string; userDisplayName?: string;
}

/** Encrypt a freshly generated credential into the server's Fido2CredentialData shape (all EncStrings)
 *  under the given key (account UserKey for a new personal cipher, or the target cipher's field key). */
export async function encryptFido2Credential(cred: NewFido2Credential, key: SymmetricKey): Promise<Fido2CredentialData> {
  const enc = (v: string) => encryptToText(v, key);
  const opt = async (v: string | undefined) => (v ? await enc(v) : null);
  return {
    credentialId: await enc(cred.credentialId),
    keyType: await enc('public-key'),
    keyAlgorithm: await enc('ECDSA'),
    keyCurve: await enc('P-256'),
    keyValue: await enc(cred.keyValue),
    rpId: await enc(cred.rpId),
    userHandle: await opt(cred.userHandle),
    userName: await opt(cred.userName),
    counter: await enc(String(cred.counter)),
    rpName: await opt(cred.rpName),
    userDisplayName: await opt(cred.userDisplayName),
    discoverable: await enc('true'),
  };
}

export { bytesToBase64Url };
```

- [ ] **Step 5: Run to verify pass**

Run: `npx vitest run src/core/vault/fido2-create.test.ts src/core/vault/fido2.test.ts`
Expected: PASS (including the keypair round-trip).

- [ ] **Step 6: Commit**

```bash
git add src/core/vault/fido2-create.ts src/core/vault/fido2.ts src/core/vault/fido2-create.test.ts src/core/vault/fido2.test.ts
git commit -m "feat: WebAuthn attestation crypto (fido2-create) + BE/BS flags on assertion"
```

---

### Task 4: Move the assertion trust boundary into the worker (harden delivered get path)

**Files:**
- Modify: `src/core/vault/vault-service.ts` (`assertRpIdForOrigin`; apply in `getPasskeyAssertion` + `hasMatchingPasskey`; `findPasskeyCredential` try/catch)
- Modify: `src/messaging/protocol.ts` (`vault.hasPasskey` gains `origin`)
- Modify: `src/background/router.ts` (`vault.hasPasskey` passes `origin`)
- Modify: `src/content/webauthn-bridge.ts` (get-relay stamps `origin=location.origin`, gates `isSecureContext`, sends `origin` to `hasPasskey`)
- Test: `src/core/vault/vault-service.test.ts`, `src/background/router.test.ts`

**Interfaces:**
- Consumes: `isRegistrableRpId` (Task 1).
- Produces: `hasMatchingPasskey({ rpId, origin, allowedCredentialIds? })` (adds required `origin`); private `assertRpIdForOrigin(rpId, origin)`. Both `getPasskeyAssertion` and `hasMatchingPasskey` reject a cross-origin rpId.

- [ ] **Step 1: Write the failing tests**

In `src/core/vault/vault-service.test.ts`, find the existing passkey tests (search `getPasskeyAssertion` / `hasMatchingPasskey`) and add a describe block (adapt fixtures to the file's existing passkey-cipher seeding helper):

```ts
describe('passkey rpId/origin trust boundary', () => {
  it('getPasskeyAssertion rejects an rpId that is not valid for the origin', async () => {
    const { service } = await makeServiceWithPasskey({ rpId: 'example.com' }); // existing helper
    await expect(service.getPasskeyAssertion({ rpId: 'example.com', origin: 'https://evil.com', challenge: 'AAAA' }))
      .rejects.toThrow(/rpId is not valid/i);
  });
  it('hasMatchingPasskey rejects a public-suffix rpId', async () => {
    const { service } = await makeServiceWithPasskey({ rpId: 'github.io' });
    await expect(service.hasMatchingPasskey({ rpId: 'github.io', origin: 'https://a.github.io' }))
      .rejects.toThrow(/rpId is not valid/i);
  });
  it('getPasskeyAssertion still signs for a valid rpId/origin', async () => {
    const { service } = await makeServiceWithPasskey({ rpId: 'example.com' });
    const res = await service.getPasskeyAssertion({ rpId: 'example.com', origin: 'https://app.example.com', challenge: 'AAAA' });
    expect(res?.credentialId).toBeTruthy();
  });
});
```

> Implementer note: reuse the existing passkey-seeding helper in this test file (the one backing the current `getPasskeyAssertion` tests). If none is factored out, seed a personal login cipher with one fido2Credential at `rpId` exactly as the current passkey tests do.

In `src/background/router.test.ts`, add:

```ts
it('vault.hasPasskey forwards origin and allowedCredentialIds', async () => {
  const hasMatchingPasskey = vi.fn(async () => true);
  const router = createRouter({ auth: {}, vault: { hasMatchingPasskey }, settings: fullSettingsStub() });
  await expect(router.handle({ type: 'vault.hasPasskey', rpId: 'example.com', origin: 'https://example.com', allowedCredentialIds: ['a'] }))
    .resolves.toEqual({ ok: true, data: { matches: true } });
  expect(hasMatchingPasskey).toHaveBeenCalledWith({ rpId: 'example.com', origin: 'https://example.com', allowedCredentialIds: ['a'] });
});
```

> Implementer note: `fullSettingsStub()` stands for the full `settings` stub object every router test in the file repeats — copy that inline object (getServerUrl…saveClipboardClearSetting) as the other tests do; do not introduce a shared helper if the file doesn't already have one.

- [ ] **Step 2: Run to verify fail**

Run: `npx vitest run src/core/vault/vault-service.test.ts src/background/router.test.ts -t passkey`
Expected: FAIL — no origin validation; `hasMatchingPasskey` doesn't accept/forward `origin`.

- [ ] **Step 3: Implement worker validation + try/catch**

In `src/core/vault/vault-service.ts`:

Add the import (top of file, with the other `./domain.js` or model imports): `import { isRegistrableRpId } from './domain.js';` (if domain isn't already imported here, add it).

Add the helper (near the other private helpers, e.g. after `cipherOwningKey`):

```ts
  /** Enforce the passkey trust boundary in the worker: the rpId must be a registrable-domain suffix of
   *  the frame origin's host (PSL-checked). The content-script bridge supplies `origin` from its own
   *  location, so the page cannot forge a cross-origin rpId. */
  private assertRpIdForOrigin(rpId: string, origin: string): void {
    let host: string;
    try { host = new URL(origin).hostname; } catch { throw new AppError('error', 'Invalid origin'); }
    if (!isRegistrableRpId(rpId, host)) throw new AppError('error', 'rpId is not valid for this origin');
  }
```

In `getPasskeyAssertion` (line 571), add as the first line of the body:
```ts
    this.assertRpIdForOrigin(params.rpId, params.origin);
```

Change `hasMatchingPasskey` (line 597) signature + body:
```ts
  async hasMatchingPasskey(params: { rpId: string; origin: string; allowedCredentialIds?: string[] }): Promise<boolean> {
    this.assertRpIdForOrigin(params.rpId, params.origin);
    return (await this.findPasskeyCredential(params.rpId, params.allowedCredentialIds)) !== undefined;
  }
```

In `findPasskeyCredential` (line 609-618 loop), wrap the decrypt so one bad cipher can't break all assertions:
```ts
    for (const cipher of cache.ciphers) {
      if (cipher.type !== 1 || !cipher.login?.fido2Credentials?.length) continue;
      if (cipher.deletedDate) continue; // trashed passkeys must not authenticate
      let decrypted;
      try {
        decrypted = await decryptCipher(cipher, userKey, orgKeys);
      } catch {
        continue; // a single undecryptable cipher must not poison passkey lookup for all rpIds
      }
      for (const cred of decrypted?.fido2Credentials ?? []) {
        if (cred.rpId !== rpId) continue;
        if (allowedCredentialIds?.length && !allowedCredentialIds.includes(cred.credentialId)) continue;
        return cred;
      }
    }
```

- [ ] **Step 4: Implement protocol + router + bridge**

In `src/messaging/protocol.ts`, change the `vault.hasPasskey` request variant (line 130) to add `origin`:
```ts
  | { type: 'vault.hasPasskey'; rpId: string; origin: string; allowedCredentialIds?: string[] }
```

In `src/background/router.ts`, update the `vault.hasPasskey` case (lines 176-183) to pass origin:
```ts
          case 'vault.hasPasskey': {
            if (!deps.vault.hasMatchingPasskey) throw new Error('vault.hasMatchingPasskey is not wired');
            const matches = await deps.vault.hasMatchingPasskey({
              rpId: request.rpId,
              origin: request.origin,
              ...(request.allowedCredentialIds ? { allowedCredentialIds: request.allowedCredentialIds } : {}),
            });
            return { ok: true, data: { matches } };
          }
```

In `src/content/webauthn-bridge.ts`, in `relay` (lines 36-59) stamp origin from the bridge's own `location` and gate secure context. Replace the two `sendRequest` payloads' `origin`/rpId sourcing so both use bridge-derived values:
```ts
async function relay(id: string, payload: AssertionPayload): Promise<void> {
  try {
    if (!window.isSecureContext) return fallback(id);
    const origin = location.origin; // trust boundary: never use page-supplied origin
    // 1) Only engage when the vault holds a matching passkey for this (worker-validated) rpId.
    const probe = await sendRequest({
      type: 'vault.hasPasskey',
      rpId: payload.rpId,
      origin,
      allowedCredentialIds: payload.allowedCredentialIds,
    });
    if (!(probe.ok && probe.data && 'matches' in probe.data && probe.data.matches)) return fallback(id);
    if (!(await confirmPasskeyUse(payload.rpId))) return fallback(id);
    const userVerified = payload.userVerification !== 'discouraged';
    const response = await sendRequest({
      type: 'vault.getPasskeyAssertion',
      rpId: payload.rpId,
      origin,
      challenge: payload.challenge,
      allowedCredentialIds: payload.allowedCredentialIds,
      userVerified,
    });
    if (response.ok && response.data && 'assertion' in response.data) {
      window.postMessage({ source: RESPONSE, id, assertion: response.data.assertion }, location.origin);
    } else {
      fallback(id);
    }
  } catch {
    fallback(id);
  }
}
```

- [ ] **Step 5: Run to verify pass**

Run: `npx vitest run src/core/vault/vault-service.test.ts src/background/router.test.ts && npm run typecheck`
Expected: PASS; typecheck clean (the `hasPasskey` message now requires `origin`, so the bridge — its only other caller — must compile with the new field, which Step 4 provides).

- [ ] **Step 6: Commit**

```bash
git add src/core/vault/vault-service.ts src/messaging/protocol.ts src/background/router.ts src/content/webauthn-bridge.ts src/core/vault/vault-service.test.ts src/background/router.test.ts
git commit -m "fix(security): validate passkey rpId against frame origin in the worker (PSL); bridge stamps origin; isolate undecryptable ciphers"
```

---

### Task 5: Worker registration — `getPasskeyTargets` + `createPasskey`

**Files:**
- Modify: `src/core/vault/vault-service.ts`
- Modify: `src/core/vault/models.ts` (add `PasskeyTarget`)
- Test: `src/core/vault/vault-service.test.ts`

**Interfaces:**
- Consumes: `isRegistrableRpId`, `getHostAndPort` (domain.ts); `generateFido2Keypair`, `buildAttestationObject`, `buildCreateClientDataJSON`, `encryptFido2Credential`, `bytesToBase64Url` (Task 3); `cipherFieldKey` (existing, vault-service.ts:227); `encryptCipher` (encrypt.ts); `api.createCipher`/`api.updateCipher` (both return `CipherResponse`); `VAULT_CACHE_KEY`, `SUMMARY_CACHE_KEY`, `findCachedCipher`, `requireUserKey`, `requireToken`.
- Produces:
  - `PasskeyTarget = { id: string; name: string; username?: string }` (models.ts)
  - `getPasskeyTargets(params: { rpId: string; origin: string }): Promise<PasskeyTarget[]>`
  - `createPasskey(params: CreatePasskeyParams): Promise<Fido2Registration>` where
    `CreatePasskeyParams = { rpId; rpName?; userHandle?; userName?; userDisplayName?; challenge; origin; userVerified?: boolean; targetCipherId?: string }` and
    `Fido2Registration = { credentialId: string; attestationObject: string; clientDataJSON: string; authData: string; publicKeySpki: string; publicKeyAlgorithm: -7 }` (all base64url except the number).

- [ ] **Step 1: Write the failing tests**

Add `PasskeyTarget`/`Fido2Registration` are needed first; write tests in `src/core/vault/vault-service.test.ts` (reuse the passkey-seeding + a personal-login-seeding helper the file already has for CRUD tests):

```ts
describe('passkey registration', () => {
  it('getPasskeyTargets returns same-domain personal logins as {id,name,username} only', async () => {
    const { service } = await makeServiceWithLogins([
      { id: 'c1', name: 'Example', username: 'me', uris: ['https://example.com/login'] },
      { id: 'c2', name: 'Other', username: 'x', uris: ['https://other.com'] },
    ]); // seeds SUMMARY_CACHE + VAULT_CACHE via a sync fixture
    const targets = await service.getPasskeyTargets({ rpId: 'example.com', origin: 'https://example.com' });
    expect(targets).toEqual([{ id: 'c1', name: 'Example', username: 'me' }]);
  });

  it('getPasskeyTargets rejects a cross-origin rpId', async () => {
    const { service } = await makeServiceWithLogins([]);
    await expect(service.getPasskeyTargets({ rpId: 'example.com', origin: 'https://evil.com' })).rejects.toThrow(/rpId is not valid/i);
  });

  it('createPasskey (new item) POSTs a login with an encrypted fido2Credential and returns an attestation', async () => {
    const createCipher = vi.fn(async (_t, req) => ({ id: 'new1', ...req } as any));
    const { service } = await makeUnlockedService({ api: { createCipher } });
    const reg = await service.createPasskey({ rpId: 'example.com', rpName: 'Example', userHandle: 'dXNlcg', userName: 'me', challenge: 'AAAA', origin: 'https://example.com', userVerified: true });
    expect(reg.publicKeyAlgorithm).toBe(-7);
    expect(reg.credentialId && reg.attestationObject && reg.clientDataJSON && reg.authData && reg.publicKeySpki).toBeTruthy();
    const [, req] = createCipher.mock.calls[0]!;
    expect(req.type).toBe(1);
    expect(req.login.fido2Credentials).toHaveLength(1);
    expect(req.login.fido2Credentials[0].keyValue).toMatch(/^2\./); // an EncString
  });

  it('createPasskey (append) PUTs the original cipher verbatim + [old, new] passkeys, without re-encrypting old fields', async () => {
    const updateCipher = vi.fn(async (_t, _id, req) => ({ id: 'c1', ...req } as any));
    // Seed a personal login c1 for example.com that already has one (encrypted) passkey.
    const { service, originalRequestSnapshot } = await makeServiceWithExistingPasskeyLogin({ id: 'c1', rpId: 'example.com', api: { updateCipher } });
    const reg = await service.createPasskey({ rpId: 'example.com', userHandle: 'dXNlcg', userName: 'me', challenge: 'AAAA', origin: 'https://example.com', targetCipherId: 'c1' });
    expect(reg.credentialId).toBeTruthy();
    const [, id, req] = updateCipher.mock.calls[0]!;
    expect(id).toBe('c1');
    expect(req.login.fido2Credentials).toHaveLength(2);
    // old passkey EncStrings are byte-identical to the original (no re-encryption)
    expect(req.login.fido2Credentials[0]).toEqual(originalRequestSnapshot.login.fido2Credentials[0]);
    // other fields carried verbatim from the original CipherResponse
    expect(req.name).toBe(originalRequestSnapshot.name);
    expect(req.login.password).toBe(originalRequestSnapshot.login.password);
  });

  it('createPasskey rejects a targetCipherId that is not a same-domain personal login', async () => {
    const { service } = await makeServiceWithLogins([{ id: 'c2', name: 'Other', username: 'x', uris: ['https://other.com'] }]);
    await expect(service.createPasskey({ rpId: 'example.com', challenge: 'AAAA', origin: 'https://example.com', targetCipherId: 'c2' })).rejects.toThrow(/not a valid target/i);
  });

  it('createPasskey throws when locked', async () => {
    const { service } = await makeLockedService();
    await expect(service.createPasskey({ rpId: 'example.com', challenge: 'AAAA', origin: 'https://example.com' })).rejects.toThrow();
  });

  it('after createPasskey the new passkey is immediately assertable (cache merged, not full sync)', async () => {
    const createCipher = vi.fn(async (_t, req) => ({ id: 'new1', ...req } as any));
    const { service } = await makeUnlockedService({ api: { createCipher } });
    await service.createPasskey({ rpId: 'example.com', userHandle: 'dXNlcg', challenge: 'AAAA', origin: 'https://example.com', userVerified: true });
    expect(await service.hasMatchingPasskey({ rpId: 'example.com', origin: 'https://example.com' })).toBe(true);
  });
});
```

> Implementer note: the test file already seeds unlocked services + cached ciphers for the existing CRUD/passkey tests. Reuse those seeding helpers; the names above (`makeUnlockedService`, `makeServiceWithLogins`, `makeServiceWithExistingPasskeyLogin`, `makeLockedService`, `originalRequestSnapshot`) are illustrative — match the file's actual helpers, and where one doesn't exist, build the fixture the same way neighboring tests do (a `SyncResponse` written to `VAULT_CACHE_KEY` + `SUMMARY_CACHE_KEY`, a UserKey in session). The behavioral assertions (call shapes, `[old,new]`, verbatim old EncStrings, cache-merge assertability, rejections) are the contract — keep them.

- [ ] **Step 2: Run to verify fail**

Run: `npx vitest run src/core/vault/vault-service.test.ts -t "passkey registration"`
Expected: FAIL — `getPasskeyTargets`/`createPasskey` not functions.

- [ ] **Step 3: Add the models type**

In `src/core/vault/models.ts`, after `DecryptedFido2Credential` (line 107), add:

```ts
/** A candidate login item a new passkey can be saved into (display-only; carries no secrets). */
export interface PasskeyTarget {
  id: string;
  name: string;
  username?: string;
}
```

- [ ] **Step 4: Implement in vault-service.ts**

Add imports at the top of `src/core/vault/vault-service.ts`:
```ts
import { getHostAndPort, isRegistrableRpId } from './domain.js';
import { generateFido2Keypair, buildAttestationObject, buildCreateClientDataJSON, encryptFido2Credential, bytesToBase64Url } from './fido2-create.js';
import type { PasskeyTarget } from './models.js';
import type { CipherRequest, CipherResponse, Fido2CredentialData, SyncResponse } from '../api/types.js';
```
(Only add the symbols not already imported — several of these types are already imported; do not duplicate.)

Add the registration result type near the top-level types in the file (or export from models — keep it local to the service alongside the methods):
```ts
export interface Fido2Registration {
  credentialId: string;
  attestationObject: string;
  clientDataJSON: string;
  authData: string;
  publicKeySpki: string;
  publicKeyAlgorithm: -7;
}
```

Add the two methods (place them right after `hasMatchingPasskey`):

```ts
  /** Same-domain personal login items a new passkey could be saved into (for the create picker).
   *  Reads the decrypted summary cache — carries only id/name/username, never secrets. */
  async getPasskeyTargets(params: { rpId: string; origin: string }): Promise<PasskeyTarget[]> {
    this.assertRpIdForOrigin(params.rpId, params.origin);
    const summaries = (await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY)) ?? [];
    const out: PasskeyTarget[] = [];
    for (const s of summaries) {
      if (s.type !== 1 || s.organizationId || s.deletedDate || s.undecryptable) continue;
      const matches = s.loginUris.some((u) => {
        const host = getHostAndPort(u.uri)?.host;
        return host ? isRegistrableRpId(params.rpId, host) : false;
      });
      if (!matches) continue;
      out.push(s.username ? { id: s.id, name: s.name, username: s.username } : { id: s.id, name: s.name });
    }
    return out;
  }

  /** Generate an ES256 passkey, build its attestation, store it (new personal login OR appended to a
   *  same-domain personal login the picker offered), merge the returned cipher into the cache, and
   *  return the attestation. The private key never leaves the worker. */
  async createPasskey(params: {
    rpId: string; rpName?: string; userHandle?: string; userName?: string; userDisplayName?: string;
    challenge: string; origin: string; userVerified?: boolean; targetCipherId?: string;
  }): Promise<Fido2Registration> {
    this.assertRpIdForOrigin(params.rpId, params.origin);
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();

    const keypair = await generateFido2Keypair();
    const credentialIdB64 = bytesToBase64Url(keypair.credentialId);
    const { attestationObject, authData } = await buildAttestationObject({
      rpId: params.rpId, coseKey: keypair.coseKey, credentialId: keypair.credentialId,
      userVerified: params.userVerified ?? false,
    });
    const clientDataJSON = buildCreateClientDataJSON(params.challenge, params.origin);
    const newCredPlain = {
      credentialId: credentialIdB64,
      keyValue: bytesToBase64Url(keypair.pkcs8),
      rpId: params.rpId,
      counter: 0,
      ...(params.userHandle ? { userHandle: params.userHandle } : {}),
      ...(params.userName ? { userName: params.userName } : {}),
      ...(params.rpName ? { rpName: params.rpName } : {}),
      ...(params.userDisplayName ? { userDisplayName: params.userDisplayName } : {}),
    };

    let saved: CipherResponse;
    if (params.targetCipherId) {
      // Re-resolve the target through the same domain match — never trust the caller-supplied id.
      const allowed = await this.getPasskeyTargets({ rpId: params.rpId, origin: params.origin });
      if (!allowed.some((t) => t.id === params.targetCipherId)) throw new AppError('error', 'Target is not a valid target for this passkey');
      const original = await this.findCachedCipher(params.targetCipherId);
      if (!original || original.type !== 1 || original.organizationId || original.deletedDate) throw new AppError('error', 'Target is not a valid target for this passkey');
      const fieldKey = await this.cipherFieldKey(original);
      const newCred = await encryptFido2Credential(newCredPlain, fieldKey);
      const request = this.cipherResponseToRequest(original);
      request.login = { ...(request.login ?? {}), fido2Credentials: [...(original.login?.fido2Credentials ?? []), newCred] };
      saved = await this.deps.api.updateCipher(token, params.targetCipherId, request);
    } else {
      const newCred = await encryptFido2Credential(newCredPlain, userKey);
      const request = await encryptCipher({
        type: 1, name: params.rpName || params.rpId,
        login: { ...(params.userName ? { username: params.userName } : {}), uris: [{ uri: `https://${params.rpId}` }] },
      }, userKey);
      request.login = { ...(request.login ?? {}), fido2Credentials: [newCred] };
      saved = await this.deps.api.createCipher(token, request);
    }

    // Best-effort cache merge so the new passkey is immediately assertable; a merge failure must NOT
    // fail the (already-succeeded) server write — the attestation is returned regardless.
    try { await this.mergeCipherIntoCache(saved); } catch { /* next sync will reconcile */ }

    return {
      credentialId: credentialIdB64,
      attestationObject: bytesToBase64Url(attestationObject),
      clientDataJSON: bytesToBase64Url(new TextEncoder().encode(clientDataJSON)),
      authData: bytesToBase64Url(authData),
      publicKeySpki: bytesToBase64Url(keypair.publicKeySpki),
      publicKeyAlgorithm: -7,
    };
  }

  /** Build a wholesale CipherRequest from an existing CipherResponse, carrying every field verbatim
   *  (all already EncStrings). Used by the passkey-append path to avoid re-encrypting/dropping fields. */
  private cipherResponseToRequest(c: CipherResponse): CipherRequest {
    const req: CipherRequest = { type: c.type, name: c.name };
    if (c.notes != null) req.notes = c.notes;
    if (c.favorite != null) req.favorite = c.favorite;
    if (c.folderId != null) req.folderId = c.folderId;
    if (c.organizationId != null) req.organizationId = c.organizationId;
    if (c.login != null) req.login = { ...c.login };
    if (c.card != null) req.card = c.card;
    if (c.identity != null) req.identity = c.identity;
    if (c.secureNote != null) req.secureNote = c.secureNote;
    if (c.key != null) req.key = c.key;
    if (c.fields != null) req.fields = c.fields;
    if (c.passwordHistory != null) req.passwordHistory = c.passwordHistory;
    if (c.reprompt != null) req.reprompt = c.reprompt;
    return req;
  }

  /** Replace-or-insert a server cipher representation into the raw sync cache (so findPasskeyCredential
   *  sees it immediately). Does not rebuild the decrypted summary caches — the popup re-syncs. */
  private async mergeCipherIntoCache(cipher: CipherResponse): Promise<void> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) return;
    const idx = cache.ciphers.findIndex((c) => c.id === cipher.id);
    if (idx >= 0) cache.ciphers[idx] = cipher; else cache.ciphers.push(cipher);
    await this.deps.localStore.set(VAULT_CACHE_KEY, cache);
  }
```

> Note: `CipherResponse` may not model `reprompt`/`favorite` identically to `CipherRequest`; copy only the fields that exist on `CipherResponse` (check `api/types.ts` `CipherResponse`) — the goal is verbatim carry-forward of whatever the server returned. If a field is absent on `CipherResponse`, omit it.

- [ ] **Step 5: Run to verify pass**

Run: `npx vitest run src/core/vault/vault-service.test.ts && npm run typecheck`
Expected: PASS; typecheck clean.

- [ ] **Step 6: Commit**

```bash
git add src/core/vault/vault-service.ts src/core/vault/models.ts src/core/vault/vault-service.test.ts
git commit -m "feat: worker getPasskeyTargets + createPasskey (new/append, cipherFieldKey, cache merge)"
```

---

### Task 6: Protocol + router for `getPasskeyTargets` / `createPasskey`

**Files:**
- Modify: `src/messaging/protocol.ts`
- Modify: `src/background/router.ts`
- Test: `src/background/router.test.ts`

**Interfaces:**
- Consumes: `VaultService.getPasskeyTargets` / `createPasskey` (Task 5); `PasskeyTarget` (models), `Fido2Registration` (vault-service).
- Produces: request variants `vault.getPasskeyTargets` / `vault.createPasskey`; response variants `{ targets: PasskeyTarget[] }` / `{ registration: Fido2Registration }`.

- [ ] **Step 1: Write the failing tests**

In `src/background/router.test.ts` add (copy the full inline `settings` stub as the file's other tests do):

```ts
it('vault.getPasskeyTargets forwards rpId+origin and returns targets', async () => {
  const getPasskeyTargets = vi.fn(async () => [{ id: 'c1', name: 'Example', username: 'me' }]);
  const router = createRouter({ auth: {}, vault: { getPasskeyTargets }, settings: fullSettingsStub() });
  await expect(router.handle({ type: 'vault.getPasskeyTargets', rpId: 'example.com', origin: 'https://example.com' }))
    .resolves.toEqual({ ok: true, data: { targets: [{ id: 'c1', name: 'Example', username: 'me' }] } });
  expect(getPasskeyTargets).toHaveBeenCalledWith({ rpId: 'example.com', origin: 'https://example.com' });
});

it('vault.createPasskey forwards params (threading optional targetCipherId) and returns registration', async () => {
  const reg = { credentialId: 'c', attestationObject: 'a', clientDataJSON: 'j', authData: 'd', publicKeySpki: 's', publicKeyAlgorithm: -7 };
  const createPasskey = vi.fn(async () => reg);
  const router = createRouter({ auth: {}, vault: { createPasskey }, settings: fullSettingsStub() });
  await expect(router.handle({ type: 'vault.createPasskey', rpId: 'example.com', challenge: 'AAAA', origin: 'https://example.com', userVerified: true }))
    .resolves.toEqual({ ok: true, data: { registration: reg } });
  expect(createPasskey).toHaveBeenCalledWith({ rpId: 'example.com', challenge: 'AAAA', origin: 'https://example.com', userVerified: true });
});
```

- [ ] **Step 2: Run to verify fail**

Run: `npx vitest run src/background/router.test.ts -t Passkey`
Expected: FAIL — no such router cases; request types unknown.

- [ ] **Step 3: Add protocol variants**

In `src/messaging/protocol.ts`, add to `RequestMessage` (after the `vault.getPasskeyAssertion` line 131):
```ts
  | { type: 'vault.getPasskeyTargets'; rpId: string; origin: string }
  | { type: 'vault.createPasskey'; rpId: string; rpName?: string; userHandle?: string; userName?: string; userDisplayName?: string; challenge: string; origin: string; userVerified?: boolean; targetCipherId?: string }
```
Add the imports for the response types at the top: `import type { PasskeyTarget } from '../core/vault/models.js';` and `import type { Fido2Registration } from '../core/vault/vault-service.js';`. Add to `ResponseMessage` (after the assertion response line 181):
```ts
  | { ok: true; data: { targets: PasskeyTarget[] } }
  | { ok: true; data: { registration: Fido2Registration } }
```

- [ ] **Step 4: Add router cases**

In `src/background/router.ts`, after the `vault.getPasskeyAssertion` case (line 184-194), add:
```ts
          case 'vault.getPasskeyTargets': {
            if (!deps.vault.getPasskeyTargets) throw new Error('vault.getPasskeyTargets is not wired');
            return { ok: true, data: { targets: await deps.vault.getPasskeyTargets({ rpId: request.rpId, origin: request.origin }) } };
          }
          case 'vault.createPasskey': {
            if (!deps.vault.createPasskey) throw new Error('vault.createPasskey is not wired');
            const registration = await deps.vault.createPasskey({
              rpId: request.rpId,
              challenge: request.challenge,
              origin: request.origin,
              ...(request.rpName ? { rpName: request.rpName } : {}),
              ...(request.userHandle ? { userHandle: request.userHandle } : {}),
              ...(request.userName ? { userName: request.userName } : {}),
              ...(request.userDisplayName ? { userDisplayName: request.userDisplayName } : {}),
              ...(request.userVerified !== undefined ? { userVerified: request.userVerified } : {}),
              ...(request.targetCipherId ? { targetCipherId: request.targetCipherId } : {}),
            });
            return { ok: true, data: { registration } };
          }
```

- [ ] **Step 5: Run to verify pass**

Run: `npx vitest run src/background/router.test.ts && npm run typecheck`
Expected: PASS; typecheck clean.

- [ ] **Step 6: Commit**

```bash
git add src/messaging/protocol.ts src/background/router.ts src/background/router.test.ts
git commit -m "feat: protocol + router for vault.getPasskeyTargets / vault.createPasskey"
```

---

### Task 7: Bridge create-relay + registration picker

**Files:**
- Modify: `src/content/webauthn-bridge.ts`
- Modify: `src/content/passkey-consent.ts` (add `renderPasskeyPickerInto` + `choosePasskeyTarget`)
- Test: `src/content/passkey-consent.test.ts`

**Interfaces:**
- Consumes: `sendRequest`; `vault.getPasskeyTargets` / `vault.createPasskey` / `vault.hasPasskey` (Tasks 4/6).
- Produces: bridge listens for `'vw-webauthn-create-request'` and posts `'vw-webauthn-create-response'`; `choosePasskeyTarget(rpId, targets): Promise<{ cancelled: true } | { targetCipherId?: string }>`; `renderPasskeyPickerInto(root, rpId, targets, onResult)` (exported for tests, mirroring `renderConsentInto`).

- [ ] **Step 1: Write the failing tests**

In `src/content/passkey-consent.test.ts` (mirror the existing `renderConsentInto` tests), add:

```ts
import { renderPasskeyPickerInto } from './passkey-consent.js';

describe('renderPasskeyPickerInto', () => {
  function setup(targets: Array<{ id: string; name: string; username?: string }>) {
    const root = document.createElement('div');
    document.body.append(root);
    let result: { cancelled: true } | { targetCipherId?: string } | undefined;
    renderPasskeyPickerInto(root, 'example.com', targets, (r) => { result = r; });
    return { root, get: () => result };
  }
  it('picking "New login item" resolves with no targetCipherId', () => {
    const { root, get } = setup([{ id: 'c1', name: 'Example', username: 'me' }]);
    (root.querySelector('#vw-pk-new') as HTMLButtonElement).dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(get()).toEqual({});
  });
  it('picking an existing target resolves with its id', () => {
    const { root, get } = setup([{ id: 'c1', name: 'Example', username: 'me' }]);
    (root.querySelector('[data-target="c1"]') as HTMLButtonElement).dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(get()).toEqual({ targetCipherId: 'c1' });
  });
  it('cancel resolves cancelled', () => {
    const { root, get } = setup([]);
    (root.querySelector('#vw-pk-cancel') as HTMLButtonElement).dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(get()).toEqual({ cancelled: true });
  });
  it('ignores untrusted (synthetic) clicks only when isTrusted is enforced', () => {
    // renderPasskeyPickerInto gates on e.isTrusted; happy-dom MouseEvent has isTrusted=false, so the
    // production dialog would ignore it. This test documents the guard by asserting the handler checks it.
    const { root, get } = setup([{ id: 'c1', name: 'Example' }]);
    // A trusted click is simulated by the test harness override used in the sibling consent tests.
    (root.querySelector('#vw-pk-new') as HTMLButtonElement).click(); // .click() → isTrusted false in happy-dom
    expect(get()).toBeUndefined();
  });
});
```

> Implementer note: the existing `passkey-consent.test.ts` establishes how this repo simulates trusted clicks (it dispatches events and/or stubs `isTrusted`). Match that exact technique so the first three tests actually fire the handler (the sibling `renderConsentInto` tests already do this). The 4th test asserts the `isTrusted` guard exists; if the sibling tests dispatch trusted events via a helper, use the same helper for the first three and a raw `.click()` for the 4th.

- [ ] **Step 2: Run to verify fail**

Run: `npx vitest run src/content/passkey-consent.test.ts`
Expected: FAIL — `renderPasskeyPickerInto` not exported.

- [ ] **Step 3: Implement the picker in passkey-consent.ts**

In `src/content/passkey-consent.ts`, add after `confirmPasskeyUse`:

```ts
export type PasskeyPickerResult = { cancelled: true } | { targetCipherId?: string };

/** Render the registration picker (New item + existing same-domain items + Cancel) into `root`.
 *  `onResult` fires exactly once. Only trusted clicks count. Mirrors renderConsentInto. */
export function renderPasskeyPickerInto(
  root: ShadowRoot | HTMLElement,
  rpId: string,
  targets: Array<{ id: string; name: string; username?: string }>,
  onResult: (result: PasskeyPickerResult) => void,
): void {
  let settled = false;
  const finish = (r: PasskeyPickerResult): void => { if (!settled) { settled = true; onResult(r); } };
  const rows = targets.map((t) => `
    <button type="button" class="cancel target" data-target="${escapeHtml(t.id)}">
      ${escapeHtml(t.name)}${t.username ? ` <span class="rp">${escapeHtml(t.username)}</span>` : ''}
    </button>`).join('');
  root.innerHTML = `
    <style>${STYLE}</style>
    <div class="overlay">
      <div class="card" role="dialog" aria-modal="true" aria-label="Save passkey">
        <div class="head"><span class="mark">${SHIELD}</span><h1>Save a passkey for <span class="rp">${escapeHtml(rpId)}</span>?</h1></div>
        <p>Choose where to store this passkey in your vault.</p>
        <div class="col">
          <button type="button" class="confirm" id="vw-pk-new">New login item</button>
          ${rows}
        </div>
        <div class="row"><button type="button" class="cancel" id="vw-pk-cancel">Cancel</button></div>
      </div>
    </div>`;
  root.querySelector('#vw-pk-new')?.addEventListener('click', (e) => { if (e.isTrusted) finish({}); });
  root.querySelector('#vw-pk-cancel')?.addEventListener('click', (e) => { if (e.isTrusted) finish({ cancelled: true }); });
  for (const btn of root.querySelectorAll<HTMLButtonElement>('button[data-target]')) {
    btn.addEventListener('click', (e) => { if (e.isTrusted) finish({ targetCipherId: btn.dataset.target! }); });
  }
  root.querySelector('.overlay')?.addEventListener('click', (e) => {
    if (e.isTrusted && e.target === e.currentTarget) finish({ cancelled: true });
  });
}

/** Prompt the user to choose where to save a new passkey. Resolves cancelled on Cancel/Esc/outside click.
 *  Lives in a closed shadow root the page cannot reach. */
export function choosePasskeyTarget(
  rpId: string,
  targets: Array<{ id: string; name: string; username?: string }>,
): Promise<PasskeyPickerResult> {
  return new Promise((resolve) => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'closed' });
    (document.body ?? document.documentElement).append(host);
    let settled = false;
    const done = (r: PasskeyPickerResult): void => {
      if (settled) return;
      settled = true;
      window.removeEventListener('keydown', onKey, true);
      host.remove();
      resolve(r);
    };
    const onKey = (e: KeyboardEvent): void => { if (e.key === 'Escape') { e.preventDefault(); done({ cancelled: true }); } };
    window.addEventListener('keydown', onKey, true);
    renderPasskeyPickerInto(shadow, rpId, targets, done);
  });
}
```

Add a `.col` rule to the `STYLE` string (near `.row`): `.col { display: flex; flex-direction: column; gap: 8px; margin-bottom: 10px; } .target { text-align: left; }`.

- [ ] **Step 4: Implement the bridge create-relay**

In `src/content/webauthn-bridge.ts`, add the create constants + listener + relay. Near the top constants:
```ts
const CREATE_REQUEST = 'vw-webauthn-create-request';
const CREATE_RESPONSE = 'vw-webauthn-create-response';
```
Import the picker: `import { confirmPasskeyUse, choosePasskeyTarget } from './passkey-consent.js';`

Add a second `window` message listener (alongside the existing one):
```ts
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  const data = event.data as { source?: string; id?: string; payload?: CreatePayload };
  if (data?.source !== CREATE_REQUEST || typeof data.id !== 'string' || !data.payload) return;
  void relayCreate(data.id, data.payload);
});
```
Add the payload type + relay:
```ts
interface CreatePayload {
  rpId: string; rpName?: string; userHandle?: string; userName?: string; userDisplayName?: string;
  challenge: string; excludeCredentialIds: string[]; userVerification?: string;
}

function createFallback(id: string): void {
  window.postMessage({ source: CREATE_RESPONSE, id, error: true }, location.origin);
}

async function relayCreate(id: string, payload: CreatePayload): Promise<void> {
  try {
    if (!window.isSecureContext) return createFallback(id);
    const origin = location.origin; // trust boundary
    // Best-effort duplicate avoidance: if the RP excludes a credential we already hold, defer to native.
    if (payload.excludeCredentialIds.length) {
      const probe = await sendRequest({ type: 'vault.hasPasskey', rpId: payload.rpId, origin, allowedCredentialIds: payload.excludeCredentialIds });
      if (probe.ok && probe.data && 'matches' in probe.data && probe.data.matches) return createFallback(id);
    }
    const targetsResp = await sendRequest({ type: 'vault.getPasskeyTargets', rpId: payload.rpId, origin });
    if (!(targetsResp.ok && targetsResp.data && 'targets' in targetsResp.data)) return createFallback(id);
    const choice = await choosePasskeyTarget(payload.rpId, targetsResp.data.targets);
    if ('cancelled' in choice) return createFallback(id);
    const userVerified = payload.userVerification !== 'discouraged';
    const resp = await sendRequest({
      type: 'vault.createPasskey',
      rpId: payload.rpId,
      challenge: payload.challenge,
      origin,
      userVerified,
      ...(payload.rpName ? { rpName: payload.rpName } : {}),
      ...(payload.userHandle ? { userHandle: payload.userHandle } : {}),
      ...(payload.userName ? { userName: payload.userName } : {}),
      ...(payload.userDisplayName ? { userDisplayName: payload.userDisplayName } : {}),
      ...(choice.targetCipherId ? { targetCipherId: choice.targetCipherId } : {}),
    });
    if (resp.ok && resp.data && 'registration' in resp.data) {
      window.postMessage({ source: CREATE_RESPONSE, id, registration: resp.data.registration }, location.origin);
    } else {
      createFallback(id);
    }
  } catch {
    createFallback(id);
  }
}
```

- [ ] **Step 5: Run to verify pass + typecheck**

Run: `npx vitest run src/content/passkey-consent.test.ts && npm run typecheck`
Expected: PASS; typecheck clean.

- [ ] **Step 6: Commit**

```bash
git add src/content/webauthn-bridge.ts src/content/passkey-consent.ts src/content/passkey-consent.test.ts
git commit -m "feat: bridge create-relay + closed-shadow-root passkey registration picker"
```

---

### Task 8: MAIN-world `create` wrapper (`page-webauthn.ts`)

**Files:**
- Modify: `src/content/page-webauthn.ts`
- Test: `src/content/page-webauthn.test.ts` (create — pure fallback-decision tests)

**Interfaces:**
- Consumes: bridge messages `vw-webauthn-create-request` / `vw-webauthn-create-response` (Task 7); `bytesToBase64Url`, `base64UrlToBytes` (encoding).
- Produces: wraps `navigator.credentials.create`; helper `shouldInterceptCreate(publicKey, host): boolean` (exported for tests).

- [ ] **Step 1: Write the failing tests**

Create `src/content/page-webauthn.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { shouldInterceptCreate } from './page-webauthn.js';

const ES256 = [{ type: 'public-key', alg: -7 }];

describe('shouldInterceptCreate', () => {
  it('intercepts a same-origin ES256 platform request', () => {
    expect(shouldInterceptCreate({ rp: { id: 'example.com' }, pubKeyCredParams: ES256 } as any, 'app.example.com')).toBe(true);
  });
  it('falls back when rpId is not a suffix of host', () => {
    expect(shouldInterceptCreate({ rp: { id: 'evil.com' }, pubKeyCredParams: ES256 } as any, 'example.com')).toBe(false);
  });
  it('falls back when no ES256 param', () => {
    expect(shouldInterceptCreate({ rp: { id: 'example.com' }, pubKeyCredParams: [{ type: 'public-key', alg: -257 }] } as any, 'example.com')).toBe(false);
  });
  it('falls back for cross-platform attachment', () => {
    expect(shouldInterceptCreate({ rp: { id: 'example.com' }, pubKeyCredParams: ES256, authenticatorSelection: { authenticatorAttachment: 'cross-platform' } } as any, 'example.com')).toBe(false);
  });
  it('defaults rpId to host when rp.id is absent', () => {
    expect(shouldInterceptCreate({ rp: {}, pubKeyCredParams: ES256 } as any, 'example.com')).toBe(true);
  });
});
```

- [ ] **Step 2: Run to verify fail**

Run: `npx vitest run src/content/page-webauthn.test.ts`
Expected: FAIL — `shouldInterceptCreate` not exported.

- [ ] **Step 3: Implement the create wrapper**

In `src/content/page-webauthn.ts`, add the create constants next to the existing REQUEST/RESPONSE:
```ts
const CREATE_REQUEST = 'vw-webauthn-create-request';
const CREATE_RESPONSE = 'vw-webauthn-create-response';
```
Export the decision helper (uses the existing `isRegistrableSuffix`):
```ts
/** Whether to intercept a create() for the vault (else defer to the native authenticator). Uses the
 *  cheap MAIN-world suffix check as a native-fallback gate; the worker re-validates rpId via PSL. */
export function shouldInterceptCreate(publicKey: PublicKeyCredentialCreationOptions, host: string): boolean {
  const rpId = publicKey.rp?.id ?? host;
  if (!isRegistrableSuffix(rpId, host)) return false;
  if (!(publicKey.pubKeyCredParams ?? []).some((p) => p.alg === -7)) return false;
  if (publicKey.authenticatorSelection?.authenticatorAttachment === 'cross-platform') return false;
  return true;
}
```
Add the wrapper (mirror the existing `get` wrapper block). After the `originalGet` block:
```ts
const originalCreate = credentials?.create?.bind(credentials);
if (originalCreate && window.isSecureContext) {
  credentials!.create = async function vaultwardenCreate(options?: CredentialCreationOptions): Promise<Credential | null> {
    const publicKey = options?.publicKey;
    if (!publicKey) return originalCreate(options);
    if (options?.signal?.aborted) return originalCreate(options);
    if (!shouldInterceptCreate(publicKey, location.hostname)) return originalCreate(options);
    try {
      const registration = await requestRegistration({
        rpId: publicKey.rp?.id ?? location.hostname,
        rpName: publicKey.rp?.name,
        userHandle: bytesToBase64Url(toBytes(publicKey.user.id)),
        userName: publicKey.user.name,
        userDisplayName: publicKey.user.displayName,
        challenge: bytesToBase64Url(toBytes(publicKey.challenge)),
        excludeCredentialIds: (publicKey.excludeCredentials ?? []).map((c) => bytesToBase64Url(toBytes(c.id))),
        ...(publicKey.authenticatorSelection?.userVerification ? { userVerification: publicKey.authenticatorSelection.userVerification } : {}),
      });
      if (!registration) return originalCreate(options); // declined / no store → native
      return buildAttestationCredential(registration);
    } catch {
      return originalCreate(options);
    }
  };
}

interface BridgeRegistration {
  credentialId: string; attestationObject: string; clientDataJSON: string;
  authData: string; publicKeySpki: string; publicKeyAlgorithm: number;
}

function requestRegistration(payload: {
  rpId: string; rpName?: string; userHandle: string; userName?: string; userDisplayName?: string;
  challenge: string; excludeCredentialIds: string[]; userVerification?: string;
}): Promise<BridgeRegistration | null> {
  return new Promise((resolve) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const onMessage = (event: MessageEvent) => {
      if (event.source !== window) return;
      const data = event.data as { source?: string; id?: string; registration?: BridgeRegistration | null; error?: boolean };
      if (data?.source !== CREATE_RESPONSE || data.id !== id) return;
      window.removeEventListener('message', onMessage);
      resolve(data.error ? null : (data.registration ?? null));
    };
    window.addEventListener('message', onMessage);
    window.postMessage({ source: CREATE_REQUEST, id, payload }, location.origin);
  });
}

/** Build a duck-typed PublicKeyCredential with an AuthenticatorAttestationResponse the RP can read. */
function buildAttestationCredential(reg: BridgeRegistration): Credential {
  const rawId = base64UrlToBytes(reg.credentialId);
  const attestationObject = toArrayBuffer(base64UrlToBytes(reg.attestationObject));
  const clientDataJSON = toArrayBuffer(base64UrlToBytes(reg.clientDataJSON));
  const authData = toArrayBuffer(base64UrlToBytes(reg.authData));
  const publicKey = toArrayBuffer(base64UrlToBytes(reg.publicKeySpki));
  const response = {
    attestationObject,
    clientDataJSON,
    getAuthenticatorData: () => authData,
    getPublicKey: () => publicKey,
    getPublicKeyAlgorithm: () => reg.publicKeyAlgorithm,
    getTransports: () => [] as string[],
  };
  return {
    id: reg.credentialId,
    rawId: toArrayBuffer(rawId),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response,
    getClientExtensionResults: () => ({}),
  } as unknown as Credential;
}
```
Add `bytesToBase64Url` to the existing encoding import if not present (it already imports `bytesToBase64Url, base64UrlToBytes`).

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run src/content/page-webauthn.test.ts && npm run typecheck`
Expected: PASS; typecheck clean.

- [ ] **Step 5: Full gate — test + build**

Run: `npm run test`
Expected: full suite green.

Run: `npm run build`
Expected: build succeeds; `webauthn-bridge.js` and `page-webauthn.js` emitted.

- [ ] **Step 6: Manual browser smoke (record in the task report; CI cannot cover this)**

Load the unpacked build in Chrome, unlock the vault against the test server. On a real RP (e.g. https://webauthn.io):
1. Register a passkey → the closed-shadow picker appears with "New login item" + any same-domain items; pick New → the RP reports a successful registration; the item appears in the vault after sync.
2. Authenticate with that passkey (the delivered get path) → RP accepts (proves the attested key is usable end-to-end).
3. Register again choosing an existing item → the passkey is appended (item shows two passkeys after sync; the item's password still works).
4. On a mismatched rpId page, confirm native fallback (extension does not intercept).

If webauthn.io/browser is unavailable in the environment, record the paths as verified structurally (typecheck/build + unit round-trip) and flag the end-to-end RP acceptance as a residual.

- [ ] **Step 7: Commit**

```bash
git add src/content/page-webauthn.ts src/content/page-webauthn.test.ts
git commit -m "feat: intercept navigator.credentials.create; build duck-typed attestation credential"
```

---

## Self-Review

**1. Spec coverage:** §1 components → Tasks 1-8. §2 trust boundary (worker PSL, bridge stamps origin) → Task 1 (helper) + Task 4 (get) + Tasks 5/7 (create). §4 attestation crypto + BE/BS → Tasks 2-3. §5 storage (getPasskeyTargets, createPasskey new/append/cipherFieldKey/cache-merge/target re-resolve, findPasskeyCredential try/catch) → Tasks 4-5. §5.6 duck-typed AttestationResponse (authData/publicKeySpki/alg) → Tasks 5 (returns them) + 8 (accessors). §6 fallback table → Task 8 (`shouldInterceptCreate` + wrapper: signal, cross-platform, publicKey, alg; excludeCredentials → Task 7 bridge). §9 protocol/router → Task 6 (+ hasPasskey origin in Task 4). §8 tests → each task. ✓

**2. Placeholder scan:** No TBD/TODO. Test-helper names in Tasks 4/5/7 are explicitly flagged as "match the file's actual helpers" with the behavioral contract spelled out — this is guidance to reuse existing fixtures, not a code placeholder (the assertions are concrete). Manual-smoke residual is inherent (no automated RP).

**3. Type consistency:** `isRegistrableRpId(rpId,host)` (T1) used in T4/T5. `Fido2Registration` shape identical in T5 (produced), T6 (protocol/router), T8 (`BridgeRegistration`). `PasskeyTarget {id,name,username?}` identical T5/T6/T7. `vault.hasPasskey` gains `origin` in T4, consumed by bridge (T4) + create-relay (T7). CBOR fns (T2) consumed by T3. `bytesToBase64Url` re-exported from fido2-create (T3) used in T5. Create message names `vw-webauthn-create-request/response` identical T7/T8. ✓

## Execution Handoff

Plan complete. Recommended: Subagent-Driven Development (fresh subagent per task + two-stage review), most-capable model for the crypto (Task 3) and worker (Tasks 4-5) tasks.
