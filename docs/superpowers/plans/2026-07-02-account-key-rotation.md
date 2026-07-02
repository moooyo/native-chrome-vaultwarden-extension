# Account Key Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user rotate their account UserKey — generate a fresh UserKey, re-encrypt all personal ciphers/folders/sends + re-wrap the account private key under it, re-enroll org account-recovery, atomically via the Vaultwarden rotation endpoint; then force a re-login.

**Architecture:** Re-encryption is **EncString/key-level, never through the plaintext editor model** (which is lossy for per-item keys, passkeys, history, attachments). A pure `rewrapEncString(enc, oldKey, newKey)` = decrypt-bytes→encrypt-bytes primitive underlies a pure `rotateCipher` (keyed cipher → re-wrap only the item key, fields untouched; keyless cipher → deep-walk and re-wrap every EncString). A worker orchestrator does a fresh sync, re-encrypts everything, wraps the new UserKey, builds the atomic payload, **strictly self-verifies with the new key before the destructive POST**, then logs out (the server rotates the security stamp, killing tokens — re-login refetches the new material and auto-heals a lost response).

**Tech Stack:** TypeScript, WebCrypto (via existing `core/crypto` primitives), vitest, `LIVE=1` live tests against the disposable Vaultwarden **through an SSH tunnel** (direct `10.0.1.20:8080` is currently blocked: `ssh -L 18080:localhost:8080 test-env`, point the live test's SERVER at `http://localhost:18080`).

## Global Constraints

- **Never use `decryptCipher→encryptCipher` for re-encryption** — it corrupts per-item keys, passkeys, password history, and attachments. Re-encrypt at the EncString/key level only.
- **Keyed cipher (`cipher.key` present):** re-wrap ONLY the item key (`encryptToBytes(decryptToBytes(cipher.key, oldUserKey), newUserKey)`); leave every field/attachment/passkey/history ciphertext untouched.
- **Keyless cipher:** re-wrap every UserKey-encrypted EncString in the raw object (name, notes, login/card/identity fields, uris, fido2Credentials, custom fields, passwordHistory, attachment keys). Preserve non-EncString fields (id, type, favorite, folderId, reprompt, deletedDate, revisionDate) verbatim.
- **Fail-close (abort the whole rotation, POST nothing):** any personal cipher that fails to decrypt (MAC error); any grantor-side emergency-access grant present (`GET /emergency-access/trusted` non-empty); any org public key that can't be fetched; the strict pre-POST self-verify failing. Argon2 accounts are already blocked by the login guard.
- **Include ALL owned personal items** (organizationId==null), **including trashed** (deletedDate set) — the server requires the payload to be a superset of every owned cipher/folder/send or it rejects with 400 (it never deletes). Org ciphers are NOT sent (org-key-encrypted, unaffected).
- **Password is unchanged:** the new UserKey is wrapped under the STRETCHED CURRENT master key (`masterKeyEncryptedUserKey`); `masterKeyAuthenticationHash` and `oldMasterKeyAuthenticationHash` are both the current master-password hash.
- **On success: log out** (clear session) and route to login — do NOT hot-swap in-session key material. The server's security-stamp rotation invalidates old tokens; re-login refetches the new protectedKey/encPrivateKey.
- **Endpoint:** `POST /api/accounts/key-management/rotate-user-account-keys` (the legacy `/api/accounts/key` returns 404). Live-validated end-to-end (core payload: `accountData.ciphers` = existing CipherRequest shape + `id`; `folders` = `{id, name}`; empty `emergencyAccessUnlockData`/`organizationAccountRecoveryUnlockData` accepted).
- **English UI copy.** No i18n. Spec: `docs/superpowers/specs/2026-07-02-account-key-rotation-design.md`.

---

### Task 1: `rewrapEncString` + EncString detection (pure primitives)

**Files:**
- Create: `src/core/vault/rotate-crypto.ts`
- Create: `src/core/vault/rotate-crypto.test.ts`

**Interfaces:**
- Consumes: `decryptToBytes`, `encryptToBytes` from `../crypto/encstring.js`; `SymmetricKey` from `../crypto/keys.js`.
- Produces: `rewrapEncString(enc: string, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<string>`; `isEncString(v: unknown): v is string`; `rewrapDeep(value: unknown, oldKey, newKey): Promise<unknown>`.

- [ ] **Step 1: Write the failing tests**

Create `src/core/vault/rotate-crypto.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { rewrapEncString, isEncString, rewrapDeep } from './rotate-crypto.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { encryptToText, decryptToBytes } from '../crypto/encstring.js';

const keyA = symmetricKeyFromBytes(new Uint8Array(64).fill(1));
const keyB = symmetricKeyFromBytes(new Uint8Array(64).fill(2));
const dec = new TextDecoder();

describe('isEncString', () => {
  it('recognizes EncStrings and rejects UUIDs/numbers/dates', () => {
    expect(isEncString('2.aQ==|Yg==|Yw==')).toBe(true);
    expect(isEncString('3.abcDEF+/=')).toBe(true);
    expect(isEncString('30b56400-e5a6-4901-b512-581293d1d43a')).toBe(false);
    expect(isEncString('600000')).toBe(false);
    expect(isEncString('2026-07-02T02:00:00Z')).toBe(false);
    expect(isEncString(5)).toBe(false);
  });
});

describe('rewrapEncString', () => {
  it('re-wraps ciphertext to a new key preserving plaintext', async () => {
    const enc = await encryptToText('hello secret', keyA);
    const rewrapped = await rewrapEncString(enc, keyA, keyB);
    expect(rewrapped).not.toBe(enc);
    expect(dec.decode(await decryptToBytes(rewrapped, keyB))).toBe('hello secret');
    await expect(decryptToBytes(rewrapped, keyA)).rejects.toBeTruthy(); // old key no longer works
  });
  it('throws when the input cannot be decrypted with the old key', async () => {
    const enc = await encryptToText('x', keyA);
    await expect(rewrapEncString(enc, keyB, keyA)).rejects.toBeTruthy();
  });
});

describe('rewrapDeep', () => {
  it('re-wraps every EncString leaf and leaves other values intact', async () => {
    const obj = { id: 'u-1', type: 1, name: await encryptToText('n', keyA), nested: { note: await encryptToText('note', keyA), count: 3 }, arr: [await encryptToText('a', keyA), 'plain'] };
    const out = await rewrapDeep(obj, keyA, keyB) as typeof obj;
    expect(out.id).toBe('u-1'); expect(out.type).toBe(1); expect(out.nested.count).toBe(3); expect(out.arr[1]).toBe('plain');
    expect(dec.decode(await decryptToBytes(out.name, keyB))).toBe('n');
    expect(dec.decode(await decryptToBytes(out.nested.note, keyB))).toBe('note');
    expect(dec.decode(await decryptToBytes(out.arr[0] as string, keyB))).toBe('a');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/core/vault/rotate-crypto.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `src/core/vault/rotate-crypto.ts`**

```ts
import { decryptToBytes, encryptToBytes } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';

/** A Bitwarden EncString: "<encType digit>.<base64>[|<base64>|<base64>]". Rejects UUIDs, numbers, dates. */
export function isEncString(v: unknown): v is string {
  return typeof v === 'string' && /^\d+\.[A-Za-z0-9+/=]+(\|[A-Za-z0-9+/=]+)*$/.test(v);
}

/** Re-encrypt an EncString from oldKey to newKey (decrypt bytes then re-encrypt). Throws (MAC) if the
 *  ciphertext cannot be decrypted with oldKey — callers MUST treat that as fail-close. */
export async function rewrapEncString(enc: string, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<string> {
  return encryptToBytes(await decryptToBytes(enc, oldKey), newKey);
}

/** Deep-clone a JSON-ish value, re-wrapping every EncString leaf from oldKey to newKey. Non-EncString
 *  values (ids, numbers, dates, plain strings) pass through unchanged. Used for KEYLESS ciphers/folders
 *  whose every EncString is under the UserKey. */
export async function rewrapDeep(value: unknown, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<unknown> {
  if (isEncString(value)) return rewrapEncString(value, oldKey, newKey);
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) out.push(await rewrapDeep(item, oldKey, newKey));
    return out;
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = await rewrapDeep(v, oldKey, newKey);
    return out;
  }
  return value;
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx vitest run src/core/vault/rotate-crypto.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/vault/rotate-crypto.ts src/core/vault/rotate-crypto.test.ts
git commit -m "feat: EncString re-wrap primitives for key rotation"
```

---

### Task 2: `rotateCipher` (keyed re-wrap / keyless deep-walk / fail-close)

**Files:**
- Create: `src/core/vault/rotate.ts`
- Create: `src/core/vault/rotate.test.ts`

**Interfaces:**
- Consumes: `rewrapEncString`, `rewrapDeep` (Task 1); `decryptToBytes`, `encryptToBytes` (encstring); `CipherResponse`, `AttachmentData` (`../api/types.js`); `SymmetricKey`.
- Produces: `rotateCipher(raw: CipherResponse, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<RotatedCipher>` where `RotatedCipher` is the raw cipher object with re-wrapped key/fields + `attachments2` for keyless attachments. Throws on any undecryptable field.

- [ ] **Step 1: Write the failing tests**

Create `src/core/vault/rotate.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { rotateCipher } from './rotate.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { encryptToText, encryptToBytes, decryptToBytes } from '../crypto/encstring.js';
import type { CipherResponse } from '../api/types.js';

const oldK = symmetricKeyFromBytes(new Uint8Array(64).fill(7));
const newK = symmetricKeyFromBytes(new Uint8Array(64).fill(9));
const dec = new TextDecoder();

it('keyed cipher: re-wraps only the item key, leaves field ciphertext byte-identical', async () => {
  const itemKeyBytes = new Uint8Array(64).fill(3);
  const wrappedItemKey = await encryptToBytes(itemKeyBytes, oldK);
  const raw = { id: 'c1', type: 1, key: wrappedItemKey, name: '2.field-ciphertext-unchanged==', login: { password: '2.pw-unchanged==' } } as unknown as CipherResponse;
  const out = await rotateCipher(raw, oldK, newK) as any;
  expect(out.name).toBe('2.field-ciphertext-unchanged=='); // untouched
  expect(out.login.password).toBe('2.pw-unchanged==');
  expect(out.key).not.toBe(wrappedItemKey);
  expect([...await decryptToBytes(out.key, newK)]).toEqual([...itemKeyBytes]); // item key preserved
});

it('keyless cipher: re-wraps every EncString field under the new UserKey; preserves id/type/deletedDate', async () => {
  const raw = { id: 'c2', type: 1, deletedDate: '2026-07-01T00:00:00Z', name: await encryptToText('MyItem', oldK), notes: await encryptToText('note', oldK), login: { username: await encryptToText('u', oldK), uris: [{ uri: await encryptToText('https://x', oldK), match: null }] }, fields: [{ type: 1, name: await encryptToText('fn', oldK), value: await encryptToText('fv', oldK) }] } as unknown as CipherResponse;
  const out = await rotateCipher(raw, oldK, newK) as any;
  expect(out.id).toBe('c2'); expect(out.type).toBe(1); expect(out.deletedDate).toBe('2026-07-01T00:00:00Z');
  expect(out.login.uris[0].match).toBeNull();
  expect(dec.decode(await decryptToBytes(out.name, newK))).toBe('MyItem');
  expect(dec.decode(await decryptToBytes(out.login.username, newK))).toBe('u');
  expect(dec.decode(await decryptToBytes(out.login.uris[0].uri, newK))).toBe('https://x');
  expect(dec.decode(await decryptToBytes(out.fields[0].value, newK))).toBe('fv');
});

it('keyless cipher with attachments: re-wraps attachment keys into attachments2', async () => {
  const raw = { id: 'c3', type: 1, name: await encryptToText('n', oldK), attachments: [{ id: 'a1', key: await encryptToText('attkey', oldK), fileName: await encryptToText('file.txt', oldK), size: '10', url: 'u' }] } as unknown as CipherResponse;
  const out = await rotateCipher(raw, oldK, newK) as any;
  expect(out.attachments2).toBeDefined();
  expect(dec.decode(await decryptToBytes(out.attachments2.a1.key, newK))).toBe('attkey');
  expect(out.attachments2.a1.fileName).toBe(out.attachments.find((a: any) => a.id === 'a1').fileName); // fileName carried (re-wrapped)
});

it('throws (fail-close) when a personal cipher field cannot be decrypted with the old key', async () => {
  const raw = { id: 'c4', type: 1, name: await encryptToText('n', newK) /* wrong key */ } as unknown as CipherResponse;
  await expect(rotateCipher(raw, oldK, newK)).rejects.toBeTruthy();
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/core/vault/rotate.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `src/core/vault/rotate.ts`**

```ts
import { decryptToBytes, encryptToBytes } from '../crypto/encstring.js';
import { rewrapEncString, rewrapDeep } from './rotate-crypto.js';
import type { SymmetricKey } from '../crypto/keys.js';
import type { CipherResponse } from '../api/types.js';

export type RotatedCipher = Record<string, unknown> & { id: string };

/**
 * Re-encrypt a PERSONAL cipher under a new UserKey. Keyed ciphers (cipher.key set) re-wrap only the item
 * key — every field/attachment/passkey/history stays under the unchanged item key. Keyless ciphers re-wrap
 * every UserKey EncString field, and lift attachment keys into `attachments2` for the rotation endpoint.
 * Throws on any undecryptable field (caller fails closed).
 */
export async function rotateCipher(raw: CipherResponse, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<RotatedCipher> {
  if (raw.key) {
    // Keyed: unwrap the raw item-key bytes with the old UserKey, re-wrap under the new UserKey. Fields untouched.
    const itemKeyBytes = await decryptToBytes(raw.key, oldKey);
    return { ...(raw as unknown as Record<string, unknown>), key: await encryptToBytes(itemKeyBytes, newKey) } as RotatedCipher;
  }
  // Keyless: deep re-wrap all EncString fields under the new UserKey (excluding attachments, handled below).
  const { attachments, ...rest } = raw as unknown as Record<string, unknown> & { attachments?: unknown[] };
  const rotated = await rewrapDeep(rest, oldKey, newKey) as RotatedCipher;
  if (Array.isArray(attachments) && attachments.length > 0) {
    const attachments2: Record<string, { key: string; fileName: string }> = {};
    for (const a of attachments as Array<{ id: string; key: string; fileName: string }>) {
      attachments2[a.id] = { key: await rewrapEncString(a.key, oldKey, newKey), fileName: await rewrapEncString(a.fileName, oldKey, newKey) };
    }
    (rotated as Record<string, unknown>).attachments2 = attachments2;
    // Re-wrapped attachments are echoed in attachments2; keep the original attachments array re-wrapped too for the self-check.
    (rotated as Record<string, unknown>).attachments = await rewrapDeep(attachments, oldKey, newKey);
  }
  return rotated;
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx vitest run src/core/vault/rotate.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/vault/rotate.ts src/core/vault/rotate.test.ts
git commit -m "feat: rotateCipher (keyed key-rewrap / keyless deep-walk / attachments2 / fail-close)"
```

---

### Task 3: `rotateFolder` + `rotateSend`

**Files:**
- Modify: `src/core/vault/rotate.ts`
- Modify: `src/core/vault/rotate.test.ts`

**Interfaces:**
- Consumes: `rewrapEncString` (Task 1); `FolderResponse`, `SendResponse` (`../api/types.js`).
- Produces: `rotateFolder(raw: FolderResponse, oldKey, newKey): Promise<{ id: string; name: string }>`; `rotateSend(raw: SendResponse, oldKey, newKey): Promise<RotatedSend>` — re-wraps the send `key` EncString; all derived-field ciphertext (name/text under the HKDF-derived key) stays unchanged; preserves `id`.

- [ ] **Step 1: Write the failing tests**

Append to `src/core/vault/rotate.test.ts`:

```ts
import { rotateFolder, rotateSend } from './rotate.js';

it('rotateFolder re-wraps the name and preserves id', async () => {
  const raw = { id: 'f1', name: await encryptToText('Work', oldK) } as any;
  const out = await rotateFolder(raw, oldK, newK);
  expect(out.id).toBe('f1');
  expect(dec.decode(await decryptToBytes(out.name, newK))).toBe('Work');
});

it('rotateSend re-wraps the send key and leaves derived-field ciphertext unchanged', async () => {
  const raw = { id: 's1', key: await encryptToText('sendkeybytes', oldK), name: '2.derived-name==', text: { text: '2.derived-text==' } } as any;
  const out = await rotateSend(raw, oldK, newK) as any;
  expect(out.id).toBe('s1');
  expect(out.name).toBe('2.derived-name=='); // derived-key ciphertext untouched
  expect(dec.decode(await decryptToBytes(out.key, newK))).toBe('sendkeybytes');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/core/vault/rotate.test.ts -t rotate`
Expected: FAIL — functions not exported.

- [ ] **Step 3: Add the functions to `src/core/vault/rotate.ts`**

```ts
import type { FolderResponse, SendResponse } from '../api/types.js';

export async function rotateFolder(raw: FolderResponse, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<{ id: string; name: string }> {
  if (!raw.name) throw new Error('folder has no name to rotate');
  return { id: raw.id, name: await rewrapEncString(raw.name, oldKey, newKey) };
}

export type RotatedSend = Record<string, unknown> & { id: string };

/** Re-wrap ONLY the send key EncString; the name/text/file ciphertext is under the HKDF-derived send key,
 *  which does not change, so it is left byte-identical. */
export async function rotateSend(raw: SendResponse, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<RotatedSend> {
  const r = raw as unknown as Record<string, unknown> & { key?: string };
  if (!r.key || typeof r.key !== 'string') throw new Error('send has no key to rotate');
  return { ...r, key: await rewrapEncString(r.key, oldKey, newKey) } as RotatedSend;
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx vitest run src/core/vault/rotate.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/vault/rotate.ts src/core/vault/rotate.test.ts
git commit -m "feat: rotateFolder + rotateSend (name / send-key re-wrap)"
```

---

### Task 4: Rotation payload types + ApiClient endpoints

**Files:**
- Modify: `src/core/api/types.ts`
- Modify: `src/core/api/client.ts`
- Test: `src/core/api/client.test.ts`

**Interfaces:**
- Produces:
  - `types.ts`: `OrganizationResponse.resetPasswordEnrolled?: boolean | null`; `interface RotateKeyData { … }` (the KeyData payload, see code); `interface OrgPublicKeyResponse { publicKey: string }`; `interface UserPublicKeyResponse { publicKey: string }`; `interface EmergencyAccessGrant { id: string }`.
  - `ApiClient`: `rotateAccountKey(token, body: RotateKeyData): Promise<void>`; `getTrustedEmergencyAccess(token): Promise<EmergencyAccessGrant[]>`; `getOrganizationPublicKey(token, orgId): Promise<OrgPublicKeyResponse>`; `getAccountPublicKey(token): Promise<UserPublicKeyResponse>`.

- [ ] **Step 1: Add the types**

In `src/core/api/types.ts`: add `resetPasswordEnrolled?: boolean | null;` to `OrganizationResponse`, and append:

```ts
export interface RotateMasterPasswordUnlockData {
  kdfType: number; kdfIterations: number; kdfParallelism: number | null; kdfMemory: number | null;
  email: string; masterKeyAuthenticationHash: string; masterKeyEncryptedUserKey: string;
}
export interface RotateOrgRecoveryData { organizationId: string; resetPasswordKey: string; }
export interface RotateKeyData {
  oldMasterKeyAuthenticationHash: string;
  accountUnlockData: {
    masterPasswordUnlockData: RotateMasterPasswordUnlockData;
    emergencyAccessUnlockData: unknown[];
    organizationAccountRecoveryUnlockData: RotateOrgRecoveryData[];
  };
  accountKeys: { userKeyEncryptedAccountPrivateKey: string; accountPublicKey: string };
  accountData: { ciphers: unknown[]; folders: unknown[]; sends: unknown[] };
}
export interface OrgPublicKeyResponse { publicKey: string }
export interface UserPublicKeyResponse { publicKey: string }
export interface EmergencyAccessGrant { id: string }
```

- [ ] **Step 2: Write the failing tests**

In `src/core/api/client.test.ts`, add (match the file's `jsonResponse`/`fetchFn: vi.fn(...)` harness):

```ts
describe('key-rotation endpoints', () => {
  it('POSTs the rotate payload', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 200 }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn: fetchFn as never, localStore: createMemoryStore() });
    await api.rotateAccountKey('tok', { oldMasterKeyAuthenticationHash: 'h' } as never);
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/accounts/key-management/rotate-user-account-keys', expect.objectContaining({ method: 'POST' }));
  });
  it('GETs the trusted emergency-access list, org public key, and account public key', async () => {
    const fetchFn = vi.fn(async (u: string) => u.includes('trusted') ? jsonResponse({ data: [{ id: 'e1' }] }) : jsonResponse({ publicKey: 'PUB' }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn: fetchFn as never, localStore: createMemoryStore() });
    expect(await api.getTrustedEmergencyAccess('t')).toEqual([{ id: 'e1' }]);
    expect((await api.getOrganizationPublicKey('t', 'o1')).publicKey).toBe('PUB');
    expect((await api.getAccountPublicKey('t')).publicKey).toBe('PUB');
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run src/core/api/client.test.ts -t rotation`
Expected: FAIL — methods undefined.

- [ ] **Step 4: Add the methods**

In `src/core/api/client.ts` (import the new types from `./types.js`), add after `changeKdf`:

```ts
  async rotateAccountKey(accessToken: string, body: RotateKeyData): Promise<void> {
    await this.noBodyRequest('/api/accounts/key-management/rotate-user-account-keys', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
  }
  /** Grants where THIS user is the grantor (people who can access my vault). Non-empty => rotation fails closed. */
  async getTrustedEmergencyAccess(accessToken: string): Promise<EmergencyAccessGrant[]> {
    const res = await this.jsonRequest<{ data?: EmergencyAccessGrant[] }>('/api/emergency-access/trusted', { method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
    return res.data ?? [];
  }
  async getOrganizationPublicKey(accessToken: string, orgId: string): Promise<OrgPublicKeyResponse> {
    return this.jsonRequest<OrgPublicKeyResponse>(`/api/organizations/${encodeURIComponent(orgId)}/keys`, { method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
  }
  async getAccountPublicKey(accessToken: string): Promise<UserPublicKeyResponse> {
    return this.jsonRequest<UserPublicKeyResponse>('/api/accounts/keys', { method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
  }
```

- [ ] **Step 5: Run tests + typecheck**

Run: `npx vitest run src/core/api/client.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/core/api/types.ts src/core/api/client.ts src/core/api/client.test.ts
git commit -m "feat: rotation payload types + ApiClient rotate/emergency/org/account-key endpoints"
```

---

### Task 5: `key-rotation.ts` orchestrator

**Files:**
- Create: `src/core/session/key-rotation.ts`
- Create: `src/core/session/key-rotation.test.ts`

**Interfaces:**
- Consumes: `rotateCipher`/`rotateFolder`/`rotateSend` (Tasks 2-3); `rewrapEncString` (Task 1); ApiClient methods (Task 4); crypto (`symmetricKeyFromBytes`, `encryptToBytes`, `stretchMasterKey`, `deriveMasterKey`, `deriveMasterPasswordHash`, `rsaOaepEncrypt`, `base64ToBytes`).
- Produces: `rotateAccountKey(masterPassword: string, deps: KeyRotationDeps): Promise<void>` (deps injected: `{ api, session, verifyMasterPassword }`). On success it calls `deps.session.logout()`.

- [ ] **Step 1: Write the failing tests**

Create `src/core/session/key-rotation.test.ts` — inject a fake `api`/`session`; assert: (a) empty-vault rotation builds a payload with empty arrays, correct masterKeyEncryptedUserKey (decrypts to the new key), and calls `session.logout()`; (b) a non-empty `getTrustedEmergencyAccess` → throws before any POST; (c) a personal cipher that fails to decrypt → throws before POST; (d) org with `resetPasswordEnrolled` → fetches its public key and includes `organizationAccountRecoveryUnlockData`; (e) the pre-POST self-verify: monkeypatch a rotated cipher to be corrupt → throws, no POST. Use the real crypto primitives with in-memory keys (mirror `auth-service.test.ts` vectors for masterKey/userKey). Write concrete assertions on `api.rotateAccountKey` call args and `api.rotateAccountKey` NOT being called on the fail-close paths.

> Implementer: model the fixtures on `src/core/session/auth-service.test.ts` (it already builds a masterKey + wrapped UserKey + encrypted PrivateKey via KDF vectors). The orchestrator needs: `session.getPersistedAuth()` → `{ email, accessToken, kdfIterations, protectedKey, encPrivateKey }`; `session.loadUserKey()` → SymmetricKey; `session.loadPrivateKey()` → PKCS8 bytes; `api.sync(token)`; `api.getAccountPublicKey`; `api.getTrustedEmergencyAccess`; `api.getOrganizationPublicKey`; `api.rotateAccountKey`; `session.logout()`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/core/session/key-rotation.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `src/core/session/key-rotation.ts`**

```ts
import { symmetricKeyFromBytes, type SymmetricKey } from '../crypto/keys.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../crypto/kdf.js';
import { encryptToBytes } from '../crypto/encstring.js';
import { rsaOaepEncrypt } from '../crypto/primitives.js';
import { base64ToBytes, bytesToBase64 } from '../crypto/encoding.js';
import { decryptCipher } from '../vault/decrypt.js';
import { rotateCipher, rotateFolder, rotateSend } from '../vault/rotate.js';
import type { RotateKeyData, RotateOrgRecoveryData } from '../api/types.js';
import { AppError } from '../errors.js';

export interface KeyRotationDeps {
  api: {
    sync(token: string): Promise<any>;
    getTrustedEmergencyAccess(token: string): Promise<Array<{ id: string }>>;
    getOrganizationPublicKey(token: string, orgId: string): Promise<{ publicKey: string }>;
    getAccountPublicKey(token: string): Promise<{ publicKey: string }>;
    rotateAccountKey(token: string, body: RotateKeyData): Promise<void>;
  };
  session: {
    getPersistedAuth(): Promise<{ email: string; accessToken: string; kdfIterations: number; encPrivateKey?: string } | undefined>;
    loadUserKey(): Promise<SymmetricKey | undefined>;
    loadPrivateKey(): Promise<Uint8Array | undefined>;
    logout(): Promise<void>;
  };
  verifyMasterPassword(masterPassword: string): Promise<boolean>;
}

/** Rotate the account UserKey: fresh sync, re-encrypt everything, atomic POST, then log out. Fails closed. */
export async function rotateAccountKey(masterPassword: string, deps: KeyRotationDeps): Promise<void> {
  const auth = await deps.session.getPersistedAuth();
  if (!auth) throw new AppError('error', 'Not logged in');
  const oldUserKey = await deps.session.loadUserKey();
  if (!oldUserKey) throw new AppError('locked', 'Vault is locked');
  if (!(await deps.verifyMasterPassword(masterPassword))) throw new AppError('error', 'Master password is incorrect');
  const token = auth.accessToken;

  // Fail-close: emergency-access grants can't be re-wrapped in this milestone.
  if ((await deps.api.getTrustedEmergencyAccess(token)).length > 0) {
    throw new AppError('error', 'Remove your emergency-access contacts before rotating your encryption key.');
  }

  const sync = await deps.api.sync(token); // authoritative full current vault
  const newUserKeyBytes = crypto.getRandomValues(new Uint8Array(64));
  const newUserKey = symmetricKeyFromBytes(newUserKeyBytes);

  // Re-encrypt personal items (organizationId==null), including trashed. Fail-close on any undecryptable.
  const personal = (sync.ciphers as Array<{ organizationId?: string | null }>).filter((c) => !c.organizationId);
  const ciphers = [] as unknown[];
  for (const c of personal) ciphers.push(await rotateCipher(c as never, oldUserKey, newUserKey));
  const folders = [] as unknown[];
  for (const f of (sync.folders ?? [])) folders.push(await rotateFolder(f as never, oldUserKey, newUserKey));
  const sends = [] as unknown[];
  for (const s of (sync.sends ?? [])) sends.push(await rotateSend(s as never, oldUserKey, newUserKey));

  // Wrap the new UserKey under the current (stretched) master key; re-wrap the private key under the new UserKey.
  const masterKey = await deriveMasterKey(masterPassword, auth.email, auth.kdfIterations);
  const masterHash = await deriveMasterPasswordHash(masterKey, masterPassword);
  const masterKeyEncryptedUserKey = await encryptToBytes(newUserKeyBytes, await stretchMasterKey(masterKey));
  const pkcs8 = await deps.session.loadPrivateKey();
  if (!pkcs8) throw new AppError('error', 'Account private key unavailable');
  const userKeyEncryptedAccountPrivateKey = await encryptToBytes(pkcs8, newUserKey);
  const accountPublicKey = (await deps.api.getAccountPublicKey(token)).publicKey;

  // Org account-recovery re-enrollment for enrolled orgs.
  const orgRecovery: RotateOrgRecoveryData[] = [];
  for (const org of (sync.profile?.organizations ?? []) as Array<{ id: string; resetPasswordEnrolled?: boolean | null }>) {
    if (!org.resetPasswordEnrolled) continue;
    const pub = base64ToBytes((await deps.api.getOrganizationPublicKey(token, org.id)).publicKey);
    orgRecovery.push({ organizationId: org.id, resetPasswordKey: `4.${bytesToBase64(await rsaOaepEncrypt(pub, newUserKeyBytes))}` });
  }

  // Strict pre-POST self-verify: every re-encrypted personal cipher must decrypt with the NEW UserKey.
  for (let i = 0; i < ciphers.length; i++) {
    const check = await decryptCipher(ciphers[i] as never, newUserKey);
    if (!check || check.name === undefined) throw new AppError('error', 'Rotation self-check failed; aborting.');
  }

  const body: RotateKeyData = {
    oldMasterKeyAuthenticationHash: masterHash,
    accountUnlockData: {
      masterPasswordUnlockData: { kdfType: 0, kdfIterations: auth.kdfIterations, kdfParallelism: null, kdfMemory: null, email: auth.email, masterKeyAuthenticationHash: masterHash, masterKeyEncryptedUserKey },
      emergencyAccessUnlockData: [],
      organizationAccountRecoveryUnlockData: orgRecovery,
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey, accountPublicKey },
    accountData: { ciphers, folders, sends },
  };

  await deps.api.rotateAccountKey(token, body); // atomic; throws on non-2xx (local material unchanged, retryable)
  await deps.session.logout(); // security stamp rotated → old tokens dead; re-login refetches new material
}
```

> Note: the self-verify uses `decryptCipher`, which returns an `undecryptable` placeholder (name `(error)`) instead of throwing — so the check MUST assert the decrypted name is not the error placeholder. For a stricter guarantee, decrypt a known re-wrapped field directly; the plan's test (e) forces a corrupt cipher and asserts the abort.

- [ ] **Step 4: Run tests + typecheck**

Run: `npx vitest run src/core/session/key-rotation.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/session/key-rotation.ts src/core/session/key-rotation.test.ts
git commit -m "feat: key-rotation orchestrator (re-encrypt all, self-verify, atomic POST, logout)"
```

---

### Task 6: Wire `auth.rotateAccountKey` (AuthService + protocol + router)

**Files:**
- Modify: `src/core/session/auth-service.ts`
- Modify: `src/messaging/protocol.ts`
- Modify: `src/background/router.ts`
- Test: `src/background/router.test.ts`

**Interfaces:**
- Consumes: `rotateAccountKey` (Task 5).
- Produces: `AuthService.rotateAccountKey(masterPassword: string): Promise<void>`; request `{ type: 'auth.rotateAccountKey'; masterPassword: string }`.

- [ ] **Step 1: Write the failing test**

In `src/background/router.test.ts`, add:

```ts
it('routes auth.rotateAccountKey', async () => {
  const auth = { rotateAccountKey: vi.fn(async () => {}) };
  const router = createRouter({ auth: auth as never, vault: {} as never, settings: {} as never } as never);
  expect(await router.handle({ type: 'auth.rotateAccountKey', masterPassword: 'pw' } as never)).toEqual({ ok: true, data: null });
  expect(auth.rotateAccountKey).toHaveBeenCalledWith('pw');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/background/router.test.ts -t rotateAccountKey`
Expected: FAIL.

- [ ] **Step 3: Add the AuthService method**

In `src/core/session/auth-service.ts`, import `rotateAccountKey as runRotation` from `./key-rotation.js` and add a method (mirroring how `changeMasterPassword` is exposed):

```ts
  async rotateAccountKey(masterPassword: string): Promise<void> {
    await runRotation(masterPassword, {
      api: this.deps.api,
      session: {
        getPersistedAuth: () => this.deps.session.getPersistedAuth(),
        loadUserKey: () => this.deps.session.loadUserKey(),
        loadPrivateKey: () => this.deps.session.loadPrivateKey(),
        logout: () => this.deps.session.logout(),
      },
      verifyMasterPassword: (pw) => this.verifyMasterPassword(pw),
    });
  }
```

(Confirm `this.deps.api` exposes the four new methods — ApiClient has them from Task 4 — and `session.getPersistedAuth/loadUserKey/loadPrivateKey/logout` exist.)

- [ ] **Step 4: Add protocol + router**

In `src/messaging/protocol.ts`, add the request: `| { type: 'auth.rotateAccountKey'; masterPassword: string }`. In `src/background/router.ts`, after the `auth.changeMasterPassword` case:

```ts
          case 'auth.rotateAccountKey':
            if (!deps.auth.rotateAccountKey) throw new Error('auth.rotateAccountKey is not wired');
            await deps.auth.rotateAccountKey(request.masterPassword);
            return { ok: true, data: null };
```

- [ ] **Step 5: Run tests + typecheck**

Run: `npx vitest run src/background/router.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/core/session/auth-service.ts src/messaging/protocol.ts src/background/router.ts src/background/router.test.ts
git commit -m "feat: wire auth.rotateAccountKey through AuthService + router"
```

---

### Task 7: Popup UI — Rotate encryption key

**Files:**
- Modify: `src/ui/popup/popup.ts`

**Interfaces:**
- Consumes: `auth.rotateAccountKey` (Task 6).

- [ ] **Step 1: Add the control to the popup security editor**

Find the popup security editor where change-master-password / change-KDF live (search `auth.changeMasterPassword` / `changeKdf` in `src/ui/popup/popup.ts`). Add a "Rotate encryption key" button + a confirm flow that:
- Shows a strong warning: "This generates a new encryption key and re-encrypts your entire vault. You and all other signed-in devices will need to sign in again. This can't be undone." + a current-master-password input.
- On confirm → `const r = await sendRequest({ type: 'auth.rotateAccountKey', masterPassword: <input> })`.
- On `!r.ok` → show `r.error.message` (raw). On ok → the worker has logged out; render the login view (`render({ kind: 'loggedOut' })` or the file's equivalent post-logout render) and show "Encryption key rotated — please sign in again."
- Disable the button + show progress while in flight (rotation can take a few seconds on large vaults).

Reuse the existing security-editor markup/handlers and status helpers. English copy.

- [ ] **Step 2: Typecheck + build**

Run: `npm run typecheck && npm run build`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/ui/popup/popup.ts
git commit -m "feat: popup Rotate encryption key action (confirm + master password + logout on success)"
```

---

### Task 8: LIVE end-to-end test (through the SSH tunnel)

**Files:**
- Create: `test/live/rotate.live.test.ts`

**Interfaces:**
- Consumes: `ApiClient`, `rotateCipher`/`rotateFolder`, the crypto primitives.

- [ ] **Step 1: Write the LIVE test**

Create `test/live/rotate.live.test.ts` (gated by `LIVE=1`). SERVER defaults to `process.env.ROTATE_SERVER ?? 'http://localhost:18080'` (the SSH tunnel; direct `10.0.1.20:8080` is blocked). It: registers a throwaway account; creates a keyless login cipher (with a custom field) + a folder; syncs; builds a real rotation payload using `rotateCipher`/`rotateFolder` + the new-UserKey wrapping (mirror the orchestrator's payload assembly, empty emergency/org arrays); POSTs `rotateAccountKey`; re-logs in; syncs; asserts the cipher decrypts with the NEW UserKey and the OLD UserKey now fails; then deletes the throwaway account (`DELETE /api/accounts` with `{ masterPasswordHash }`). Add a second case that soft-deletes a cipher first and asserts it is still present + trashed after rotation.

> Assembly detail: reuse `buildRegistration` for the account, `api.createCipher(token, await encryptCipher(input, oldUserKey))` to seed, then feed the RAW synced `CipherResponse` through `rotateCipher(raw, oldUserKey, newUserKey)` (NOT re-encryptCipher) so the LIVE test exercises the real production re-encryption path.

- [ ] **Step 2: Run it (gated, tunnel up)**

Ensure the tunnel is up (`ssh -L 18080:localhost:8080 test-env`), then:
Run: `LIVE=1 npx vitest run test/live/rotate.live.test.ts`
Expected: PASS (rotate 200, round-trip verified, trashed preserved, account deleted).

- [ ] **Step 3: Confirm the non-live suite is unaffected**

Run: `npm test && npm run typecheck && npm run build`
Expected: all green; the live test is skipped without `LIVE=1`.

- [ ] **Step 4: Commit**

```bash
git add test/live/rotate.live.test.ts
git commit -m "test: live account key rotation end-to-end (LIVE-gated, via tunnel)"
```

---

## Manual verification (before ship)

- Rotate a real vault with a mix of keyed (created by an official Bitwarden client) and keyless (created by this client) ciphers, a passkey, password history, and an attachment; after rotation + re-login, confirm all decrypt, the passkey still authenticates, and the attachment downloads.
- Confirm rotation is refused when an emergency-access contact exists.

## Self-Review Notes

- **Spec coverage:** §1/§2 scope (all tasks), §3 crypto background (T1-T3), §4 contract (T4 types + T8 live), §4/§5 orchestration incl. fresh-sync/self-verify/fail-close/logout (T5), §5 client/protocol (T4/T6), §6 UI (T7), §7 security invariants (fail-close in T2/T5, no plaintext boundary, logout-not-hotswap in T5), §8 live-validated core + T8 live, §9 tests (each task). Emergency access = fail-close (T5). Attachments = re-wrap via attachments2 (T2), LIVE-verified (T8) with fail-close fallback documented.
- **Type consistency:** `rewrapEncString`/`rewrapDeep` (T1) → T2/T3; `rotateCipher`/`rotateFolder`/`rotateSend` (T2/T3) → T5; `RotateKeyData` (T4) → T5/T6; `auth.rotateAccountKey` (T6) → T7.
- **No placeholders:** crypto crux (T1-T3, T5) carries complete code; T7 UI + T5 test fixtures give concrete anchors; T8 live test structure specified with the exact assembly rule.
