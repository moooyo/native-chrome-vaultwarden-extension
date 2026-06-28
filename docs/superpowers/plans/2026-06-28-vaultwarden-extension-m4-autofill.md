# Vaultwarden Extension M4 Autofill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build native MV3 semi-automatic autofill for Vaultwarden login items with Bitwarden-like URI matching, page-side form detection, and worker-gated credential release.

**Architecture:** Service worker remains the only trusted vault/decryption boundary. Content scripts run on `http://*/*` and `https://*/*` in all frames, detect login forms, render a shadow-DOM popover, request candidates from the worker, and receive username/password only after a user selects a matching item. URI matching and form detection are isolated as pure, testable modules.

**Tech Stack:** Manifest V3, TypeScript, WebExtensions API, WebCrypto-backed M1-M3 vault services, esbuild, vitest, eslint, `tldts@latest` for public-suffix-aware domain parsing, `happy-dom@latest` for DOM unit tests. No frontend or extension framework.

## Global Constraints

- Use `npm.cmd`, not `npm`, in PowerShell.
- Keep MV3 with `background.service_worker` and `type: "module"`.
- Content scripts must be native TypeScript bundled by esbuild; do not introduce React, Vue, Svelte, Plasmo, WXT, or other extension/front-end frameworks.
- Master password, MasterKey, UserKey, access/refresh tokens, and plaintext vault data must never be logged or exposed to page scripts.
- Content scripts must not store credentials in `storage.local`, `storage.session`, DOM attributes, globals, or console output.
- Passwords are returned to content scripts only after explicit user selection and only for a cipher that still matches the current frame URL.
- Autofill must never auto-submit forms.
- Autofill must not fill hidden, disabled, or readonly inputs.
- Iframes are supported with `all_frames: true`; matching uses the frame URL, not the top-level page URL.
- `login.uris[].match` must be preserved and interpreted as Bitwarden-style strategies: Domain `0`, Host `1`, StartsWith `2`, Exact `3`, RegularExpression `4`, Never `5`.
- Empty or invalid `match` uses the settings default strategy, which defaults to Domain.
- Regular expression matching must reject overlong patterns and invalid regexes by returning no match.
- Each task must follow TDD: failing test first, implementation second, focused verification third, commit last.
- Every commit must include:

```text
Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

---

## File Structure

```text
package.json
package-lock.json
build.mjs
src/
├─ manifest.json
├─ background/
│  ├─ index.ts
│  ├─ router.ts
│  ├─ router.test.ts
│  ├─ settings.ts
│  └─ settings.test.ts
├─ content/
│  ├─ autofill.ts               # content script entry: detection + popover controller
│  ├─ autofill.test.ts
│  ├─ fill.ts                   # writes credentials into selected inputs and dispatches events
│  ├─ fill.test.ts
│  ├─ form-detection.ts         # login form detection pure DOM module
│  ├─ form-detection.test.ts
│  ├─ popover.ts                # shadow DOM popover renderer
│  └─ popover.test.ts
├─ core/
│  ├─ errors.ts                 # typed application errors surfaced through router
│  └─ vault/
│     ├─ domain.ts
│     ├─ domain.test.ts
│     ├─ uri-match.ts
│     ├─ uri-match.test.ts
│     ├─ models.ts
│     ├─ decrypt.ts
│     ├─ decrypt.test.ts
│     ├─ vault-service.ts
│     └─ vault-service.test.ts
├─ messaging/
│  └─ protocol.ts
└─ ui/
   └─ options/
      ├─ options.html
      ├─ options.ts
      └─ options.css
README.md
```

---

### Task 1: URI Match Core

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `src/core/vault/domain.ts`
- Create: `src/core/vault/domain.test.ts`
- Create: `src/core/vault/uri-match.ts`
- Create: `src/core/vault/uri-match.test.ts`

**Interfaces:**
- Produces:
  - `UriMatchStrategy`
  - `UriMatchStrategySetting`
  - `LoginUri`
  - `UriMatchResult`
  - `isUriMatchStrategySetting(value: unknown): value is UriMatchStrategySetting`
  - `matchLoginUri(loginUri: LoginUri, frameUrl: string, defaultStrategy: UriMatchStrategySetting): UriMatchResult | undefined`
  - `compareMatchResults(a: UriMatchResult, b: UriMatchResult): number`
  - `getBaseDomain(value: string): string | undefined`
  - `getHostAndPort(value: string): { host: string; port?: string } | undefined`
- Consumes: none.

- [ ] **Step 1: Install domain dependency**

Run:

```powershell
npm.cmd install tldts@latest
```

Expected: `package.json` has `tldts` in `dependencies`, and `package-lock.json` is updated.

- [ ] **Step 2: Write failing domain tests**

Create `src/core/vault/domain.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { getBaseDomain, getHostAndPort, isHttpUrl } from './domain.js';

describe('domain helpers', () => {
  it('extracts a public-suffix-aware base domain', () => {
    expect(getBaseDomain('https://login.example.com/account')).toBe('example.com');
    expect(getBaseDomain('login.example.co.uk')).toBe('example.co.uk');
  });

  it('keeps localhost and IP addresses as their own base domain', () => {
    expect(getBaseDomain('http://localhost:8080/login')).toBe('localhost');
    expect(getBaseDomain('https://127.0.0.1:8080/login')).toBe('127.0.0.1');
  });

  it('extracts host and optional port from URLs and host strings', () => {
    expect(getHostAndPort('https://vault.example.com:8443/login')).toEqual({ host: 'vault.example.com', port: '8443' });
    expect(getHostAndPort('vault.example.com')).toEqual({ host: 'vault.example.com' });
  });

  it('rejects non-http URLs for autofill matching', () => {
    expect(isHttpUrl('https://example.com')).toBe(true);
    expect(isHttpUrl('http://example.com')).toBe(true);
    expect(isHttpUrl('file:///tmp/login.html')).toBe(false);
    expect(isHttpUrl('about:blank')).toBe(false);
  });
});
```

- [ ] **Step 3: Run domain tests to verify failure**

Run:

```powershell
npm.cmd test -- src/core/vault/domain.test.ts
```

Expected: FAIL because `src/core/vault/domain.ts` does not exist.

- [ ] **Step 4: Implement domain helpers**

Create `src/core/vault/domain.ts`:

```ts
import { getDomain } from 'tldts';

export interface HostAndPort {
  host: string;
  port?: string;
}

export function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

export function getHostAndPort(value: string): HostAndPort | undefined {
  const url = parseAsUrlOrHost(value);
  if (!url) return undefined;
  const host = url.hostname.toLowerCase();
  if (!host) return undefined;
  return url.port ? { host, port: url.port } : { host };
}

export function getBaseDomain(value: string): string | undefined {
  const hostAndPort = getHostAndPort(value);
  if (!hostAndPort) return undefined;
  const host = hostAndPort.host;
  if (host === 'localhost' || isIpv4Address(host) || isIpv6Address(host)) return host;
  return getDomain(host, { allowPrivateDomains: true })?.toLowerCase() ?? host;
}

function parseAsUrlOrHost(value: string): URL | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  try {
    return new URL(trimmed);
  } catch {
    try {
      return new URL(`https://${trimmed}`);
    } catch {
      return undefined;
    }
  }
}

function isIpv4Address(value: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value);
}

function isIpv6Address(value: string): boolean {
  return value.includes(':');
}
```

- [ ] **Step 5: Write failing URI match tests**

Create `src/core/vault/uri-match.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import {
  compareMatchResults,
  isUriMatchStrategySetting,
  matchLoginUri,
  UriMatchStrategy,
} from './uri-match.js';

describe('uri matching', () => {
  it('matches by domain including subdomains and complex public suffixes', () => {
    expect(matchLoginUri({ uri: 'https://example.com', match: UriMatchStrategy.Domain }, 'https://login.example.com/auth', UriMatchStrategy.Host))
      .toMatchObject({ matchedUri: 'https://example.com', matchType: UriMatchStrategy.Domain });
    expect(matchLoginUri({ uri: 'https://example.co.uk', match: UriMatchStrategy.Domain }, 'https://id.example.co.uk/auth', UriMatchStrategy.Host))
      .toMatchObject({ matchedUri: 'https://example.co.uk', matchType: UriMatchStrategy.Domain });
    expect(matchLoginUri({ uri: 'https://evil.co.uk', match: UriMatchStrategy.Domain }, 'https://id.example.co.uk/auth', UriMatchStrategy.Host))
      .toBeUndefined();
  });

  it('matches by host and respects a saved port when present', () => {
    expect(matchLoginUri({ uri: 'https://vault.example.com', match: UriMatchStrategy.Host }, 'https://vault.example.com/login', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.Host });
    expect(matchLoginUri({ uri: 'https://vault.example.com:8443', match: UriMatchStrategy.Host }, 'https://vault.example.com/login', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'https://vault.example.com:8443', match: UriMatchStrategy.Host }, 'https://vault.example.com:8443/login', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.Host });
  });

  it('matches starts-with and exact against full URLs', () => {
    expect(matchLoginUri({ uri: 'https://example.com/login', match: UriMatchStrategy.StartsWith }, 'https://example.com/login?next=%2F', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.StartsWith });
    expect(matchLoginUri({ uri: 'https://example.com/login', match: UriMatchStrategy.Exact }, 'https://example.com/login?next=%2F', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'https://example.com/login', match: UriMatchStrategy.Exact }, 'https://example.com/login', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.Exact });
  });

  it('matches safe regular expressions and rejects invalid or overlong regular expressions', () => {
    expect(matchLoginUri({ uri: '^https://app\\.example\\.com/[a-z]+$', match: UriMatchStrategy.RegularExpression }, 'https://app.example.com/login', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.RegularExpression });
    expect(matchLoginUri({ uri: '[', match: UriMatchStrategy.RegularExpression }, 'https://app.example.com/login', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'a'.repeat(513), match: UriMatchStrategy.RegularExpression }, 'https://app.example.com/login', UriMatchStrategy.Domain))
      .toBeUndefined();
  });

  it('uses the configured default strategy when match is absent or invalid', () => {
    expect(matchLoginUri({ uri: 'https://example.com' }, 'https://login.example.com', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.Domain });
    expect(matchLoginUri({ uri: 'https://example.com', match: 99 }, 'https://login.example.com', UriMatchStrategy.Host))
      .toBeUndefined();
  });

  it('never matches Never and rejects non-http frame URLs', () => {
    expect(matchLoginUri({ uri: 'https://example.com', match: UriMatchStrategy.Never }, 'https://example.com', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'https://example.com', match: UriMatchStrategy.Domain }, 'about:blank', UriMatchStrategy.Domain))
      .toBeUndefined();
  });

  it('sorts stronger matches before weaker matches', () => {
    const exact = matchLoginUri({ uri: 'https://example.com/login', match: UriMatchStrategy.Exact }, 'https://example.com/login', UriMatchStrategy.Domain)!;
    const domain = matchLoginUri({ uri: 'https://example.com', match: UriMatchStrategy.Domain }, 'https://login.example.com/login', UriMatchStrategy.Domain)!;
    expect(compareMatchResults(exact, domain)).toBeLessThan(0);
    expect(compareMatchResults(domain, exact)).toBeGreaterThan(0);
  });

  it('recognizes only supported strategy values', () => {
    expect(isUriMatchStrategySetting(UriMatchStrategy.Domain)).toBe(true);
    expect(isUriMatchStrategySetting(UriMatchStrategy.Never)).toBe(true);
    expect(isUriMatchStrategySetting(6)).toBe(false);
    expect(isUriMatchStrategySetting('0')).toBe(false);
  });
});
```

- [ ] **Step 6: Run URI match tests to verify failure**

Run:

```powershell
npm.cmd test -- src/core/vault/uri-match.test.ts
```

Expected: FAIL because `src/core/vault/uri-match.ts` does not exist.

- [ ] **Step 7: Implement URI matching**

Create `src/core/vault/uri-match.ts`:

```ts
import { getBaseDomain, getHostAndPort, isHttpUrl } from './domain.js';

export const UriMatchStrategy = {
  Domain: 0,
  Host: 1,
  StartsWith: 2,
  Exact: 3,
  RegularExpression: 4,
  Never: 5,
} as const;

export type UriMatchStrategySetting = (typeof UriMatchStrategy)[keyof typeof UriMatchStrategy];

export interface LoginUri {
  uri: string;
  match?: number | null;
}

export interface UriMatchResult {
  matchedUri: string;
  matchType: UriMatchStrategySetting;
  score: number;
}

const MAX_REGEX_PATTERN_LENGTH = 512;

const MATCH_SCORE: Record<UriMatchStrategySetting, number> = {
  [UriMatchStrategy.Exact]: 0,
  [UriMatchStrategy.StartsWith]: 1,
  [UriMatchStrategy.Host]: 2,
  [UriMatchStrategy.Domain]: 3,
  [UriMatchStrategy.RegularExpression]: 4,
  [UriMatchStrategy.Never]: 99,
};

export function isUriMatchStrategySetting(value: unknown): value is UriMatchStrategySetting {
  return value === UriMatchStrategy.Domain
    || value === UriMatchStrategy.Host
    || value === UriMatchStrategy.StartsWith
    || value === UriMatchStrategy.Exact
    || value === UriMatchStrategy.RegularExpression
    || value === UriMatchStrategy.Never;
}

export function matchLoginUri(
  loginUri: LoginUri,
  frameUrl: string,
  defaultStrategy: UriMatchStrategySetting,
): UriMatchResult | undefined {
  if (!isHttpUrl(frameUrl)) return undefined;
  const savedUri = loginUri.uri.trim();
  if (!savedUri) return undefined;
  const strategy = isUriMatchStrategySetting(loginUri.match) ? loginUri.match : defaultStrategy;
  if (strategy === UriMatchStrategy.Never) return undefined;

  const matched = matchesStrategy(savedUri, frameUrl, strategy);
  if (!matched) return undefined;
  return { matchedUri: savedUri, matchType: strategy, score: MATCH_SCORE[strategy] };
}

export function compareMatchResults(a: UriMatchResult, b: UriMatchResult): number {
  return a.score - b.score;
}

function matchesStrategy(savedUri: string, frameUrl: string, strategy: UriMatchStrategySetting): boolean {
  switch (strategy) {
    case UriMatchStrategy.Domain:
      return domainMatches(savedUri, frameUrl);
    case UriMatchStrategy.Host:
      return hostMatches(savedUri, frameUrl);
    case UriMatchStrategy.StartsWith:
      return frameUrl.startsWith(savedUri);
    case UriMatchStrategy.Exact:
      return frameUrl === savedUri;
    case UriMatchStrategy.RegularExpression:
      return regexMatches(savedUri, frameUrl);
    case UriMatchStrategy.Never:
      return false;
  }
}

function domainMatches(savedUri: string, frameUrl: string): boolean {
  const savedDomain = getBaseDomain(savedUri);
  const frameDomain = getBaseDomain(frameUrl);
  return Boolean(savedDomain && frameDomain && savedDomain === frameDomain);
}

function hostMatches(savedUri: string, frameUrl: string): boolean {
  const saved = getHostAndPort(savedUri);
  const frame = getHostAndPort(frameUrl);
  if (!saved || !frame) return false;
  if (saved.host !== frame.host) return false;
  return saved.port === undefined || saved.port === frame.port;
}

function regexMatches(pattern: string, frameUrl: string): boolean {
  if (pattern.length > MAX_REGEX_PATTERN_LENGTH) return false;
  try {
    return new RegExp(pattern).test(frameUrl);
  } catch {
    return false;
  }
}
```

- [ ] **Step 8: Run focused tests**

Run:

```powershell
npm.cmd test -- src/core/vault/domain.test.ts src/core/vault/uri-match.test.ts
```

Expected: PASS for both test files.

- [ ] **Step 9: Commit**

Run:

```powershell
git add package.json package-lock.json src/core/vault/domain.ts src/core/vault/domain.test.ts src/core/vault/uri-match.ts src/core/vault/uri-match.test.ts
git commit -m "feat: add autofill uri matching core" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Preserve Login URI Match Metadata

**Files:**
- Modify: `src/core/vault/models.ts`
- Modify: `src/core/vault/decrypt.ts`
- Modify: `src/core/vault/decrypt.test.ts`
- Modify: `src/core/vault/vault-service.test.ts`
- Modify: `src/core/vault/search.ts`
- Modify: `src/core/vault/search.test.ts`
- Modify: `src/background/router.test.ts`

**Interfaces:**
- Consumes: `LoginUri`, `UriMatchStrategySetting` from `src/core/vault/uri-match.ts`.
- Produces:
  - `CipherSummary.loginUris: LoginUri[]`
  - `DecryptedCipher.loginUris: LoginUri[]`
  - Existing `CipherSummary.uris: string[]` remains available for popup search.

- [ ] **Step 1: Write failing decrypt test for match metadata**

In `src/core/vault/decrypt.test.ts`, update the first login cipher URI and expected output:

```ts
login: {
  username: FIELD_VECTOR.encString,
  password: FIELD_VECTOR.encString,
  totp: FIELD_VECTOR.encString,
  uris: [{ uri: FIELD_VECTOR.encString, match: 1 }],
},
```

Expected object must include:

```ts
uris: [FIELD_VECTOR.plaintext],
loginUris: [{ uri: FIELD_VECTOR.plaintext, match: 1 }],
```

Also update the item-key test expected object:

```ts
uris: ['https://example.com'],
loginUris: [{ uri: 'https://example.com', match: 0 }],
```

and set its encrypted input URI to:

```ts
uris: [{ uri: await encryptString('https://example.com', itemKey), match: 0 }],
```

- [ ] **Step 2: Run decrypt test to verify failure**

Run:

```powershell
npm.cmd test -- src/core/vault/decrypt.test.ts
```

Expected: FAIL because `loginUris` is missing.

- [ ] **Step 3: Update vault models**

Replace `src/core/vault/models.ts` with:

```ts
import type { LoginUri } from './uri-match.js';

export type FieldName = 'username' | 'password' | 'totp' | 'notes';

export interface CipherSummary {
  id: string;
  name: string;
  username?: string;
  uris: string[];
  loginUris: LoginUri[];
  type: 1 | 2 | 3 | 4 | 5;
  favorite: boolean;
  undecryptable?: boolean;
}

export interface DecryptedCipher extends CipherSummary {
  password?: string;
  totp?: string;
  notes?: string;
}
```

- [ ] **Step 4: Update decrypt implementation**

In `src/core/vault/decrypt.ts`, replace URI decryption logic with:

```ts
const loginUris = (await Promise.all(
  (cipher.login?.uris ?? []).map(async (u) => {
    if (!u.uri) return undefined;
    return { uri: await decryptToText(u.uri, key), match: u.match };
  }),
)).filter((u): u is { uri: string; match?: number | null } => Boolean(u));
```

Then set both properties in `out`:

```ts
const out: DecryptedCipher = {
  id: cipher.id,
  type: cipher.type,
  favorite: cipher.favorite ?? false,
  name,
  uris: loginUris.map((u) => u.uri),
  loginUris,
};
```

Update undecryptable summaries in `decrypt.ts` and `vault-service.ts` to include:

```ts
loginUris: [],
```

- [ ] **Step 5: Update existing tests and fixtures**

Every expected `CipherSummary` in these files must include `loginUris`:

```text
src/core/vault/vault-service.test.ts
src/core/vault/search.test.ts
src/background/router.test.ts
```

Example update:

```ts
{
  id: 'cipher-1',
  type: 1,
  favorite: false,
  name: FIELD_VECTOR.plaintext,
  username: FIELD_VECTOR.plaintext,
  uris: [FIELD_VECTOR.plaintext],
  loginUris: [{ uri: FIELD_VECTOR.plaintext }],
}
```

- [ ] **Step 6: Ensure search still searches URI text**

`src/core/vault/search.ts` should continue to use `item.uris`:

```ts
export function filterSummaries(items: CipherSummary[], query: string): CipherSummary[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((item) => {
    const haystack = [item.name, item.username ?? '', ...item.uris].join('\n').toLowerCase();
    return haystack.includes(q);
  });
}
```

- [ ] **Step 7: Run focused tests**

Run:

```powershell
npm.cmd test -- src/core/vault/decrypt.test.ts src/core/vault/vault-service.test.ts src/core/vault/search.test.ts src/background/router.test.ts
```

Expected: PASS for all four test files.

- [ ] **Step 8: Commit**

Run:

```powershell
git add src/core/vault/models.ts src/core/vault/decrypt.ts src/core/vault/decrypt.test.ts src/core/vault/vault-service.ts src/core/vault/vault-service.test.ts src/core/vault/search.ts src/core/vault/search.test.ts src/background/router.test.ts
git commit -m "feat: preserve vault uri match metadata" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Autofill Settings

**Files:**
- Create: `src/background/settings.test.ts`
- Modify: `src/background/settings.ts`
- Modify: `src/messaging/protocol.ts`
- Modify: `src/background/router.ts`
- Modify: `src/background/router.test.ts`
- Modify: `src/ui/options/options.html`
- Modify: `src/ui/options/options.ts`

**Interfaces:**
- Consumes: `UriMatchStrategy`, `UriMatchStrategySetting`, `isUriMatchStrategySetting`.
- Produces:
  - `settings.getDefaultUriMatchStrategy(): Promise<UriMatchStrategySetting>`
  - `settings.saveDefaultUriMatchStrategy(strategy: UriMatchStrategySetting): Promise<void>`
  - `settings.get` response data includes `defaultUriMatchStrategy`.
  - `settings.save` request may include `defaultUriMatchStrategy`.

- [ ] **Step 1: Write failing settings tests**

Create `src/background/settings.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { createMemoryStore } from '../platform/store.js';
import { UriMatchStrategy } from '../core/vault/uri-match.js';
import { createSettingsService } from './settings.js';

describe('settings service', () => {
  it('defaults URI match strategy to Domain', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.getDefaultUriMatchStrategy()).resolves.toBe(UriMatchStrategy.Domain);
  });

  it('persists a supported URI match strategy', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveDefaultUriMatchStrategy(UriMatchStrategy.Host);
    await expect(settings.getDefaultUriMatchStrategy()).resolves.toBe(UriMatchStrategy.Host);
  });

  it('rejects unsupported URI match strategy values', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveDefaultUriMatchStrategy(6 as never)).rejects.toThrow('unsupported URI match strategy');
  });
});
```

- [ ] **Step 2: Run settings test to verify failure**

Run:

```powershell
npm.cmd test -- src/background/settings.test.ts
```

Expected: FAIL because methods do not exist.

- [ ] **Step 3: Implement settings methods**

Update `src/background/settings.ts`:

```ts
import type { KeyValueStore } from '../platform/store.js';
import { isUriMatchStrategySetting, UriMatchStrategy, type UriMatchStrategySetting } from '../core/vault/uri-match.js';

const SERVER_URL_KEY = 'serverUrl';
const DEFAULT_URI_MATCH_STRATEGY_KEY = 'defaultUriMatchStrategy';

export function createSettingsService(store: KeyValueStore) {
  return {
    async getServerUrl(): Promise<string | undefined> {
      return store.get<string>(SERVER_URL_KEY);
    },

    async saveServerUrl(serverUrl: string): Promise<void> {
      const url = new URL(serverUrl);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        throw new Error('serverUrl must start with http:// or https://');
      }
      await store.set(SERVER_URL_KEY, url.toString());
    },

    async getDefaultUriMatchStrategy(): Promise<UriMatchStrategySetting> {
      const value = await store.get<unknown>(DEFAULT_URI_MATCH_STRATEGY_KEY);
      return isUriMatchStrategySetting(value) ? value : UriMatchStrategy.Domain;
    },

    async saveDefaultUriMatchStrategy(strategy: UriMatchStrategySetting): Promise<void> {
      if (!isUriMatchStrategySetting(strategy)) {
        throw new Error('unsupported URI match strategy');
      }
      await store.set(DEFAULT_URI_MATCH_STRATEGY_KEY, strategy);
    },
  };
}
```

- [ ] **Step 4: Update protocol settings types**

In `src/messaging/protocol.ts`, import:

```ts
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
```

Update request union settings entries:

```ts
| { type: 'settings.get' }
| { type: 'settings.save'; serverUrl: string; defaultUriMatchStrategy?: UriMatchStrategySetting };
```

Update response union settings data:

```ts
| { ok: true; data: { serverUrl?: string; defaultUriMatchStrategy: UriMatchStrategySetting } }
```

Do not add `AutofillCandidate` or `AutofillCredentials` to the response union yet; Task 4 adds those exports and Task 6 wires them.

- [ ] **Step 5: Update router settings branch and tests**

In `src/background/router.ts`, extend `RouterDeps.settings`:

```ts
getDefaultUriMatchStrategy(): Promise<UriMatchStrategySetting>;
saveDefaultUriMatchStrategy(strategy: UriMatchStrategySetting): Promise<void>;
```

Update `settings.get`:

```ts
case 'settings.get': {
  const serverUrl = await deps.settings.getServerUrl();
  const defaultUriMatchStrategy = await deps.settings.getDefaultUriMatchStrategy();
  return { ok: true, data: serverUrl === undefined ? { defaultUriMatchStrategy } : { serverUrl, defaultUriMatchStrategy } };
}
```

Update `settings.save`:

```ts
case 'settings.save':
  await deps.settings.saveServerUrl(request.serverUrl);
  if (request.defaultUriMatchStrategy !== undefined) {
    await deps.settings.saveDefaultUriMatchStrategy(request.defaultUriMatchStrategy);
  }
  return { ok: true, data: null };
```

Update every `settings` test double in `src/background/router.test.ts` to include both new methods. Add this test:

```ts
it('routes settings.get with default autofill strategy', async () => {
  const router = createRouter({
    auth: {},
    vault: {},
    settings: {
      getServerUrl: vi.fn(async () => 'https://vault.example.com'),
      saveServerUrl: vi.fn(),
      getDefaultUriMatchStrategy: vi.fn(async () => 0),
      saveDefaultUriMatchStrategy: vi.fn(),
    },
  });
  await expect(router.handle({ type: 'settings.get' }))
    .resolves.toEqual({ ok: true, data: { serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 0 } });
});
```

Add this save test:

```ts
it('routes settings.save with default autofill strategy', async () => {
  const saveServerUrl = vi.fn(async () => {});
  const saveDefaultUriMatchStrategy = vi.fn(async () => {});
  const router = createRouter({
    auth: {},
    vault: {},
    settings: {
      getServerUrl: vi.fn(),
      saveServerUrl,
      getDefaultUriMatchStrategy: vi.fn(async () => 0),
      saveDefaultUriMatchStrategy,
    },
  });
  await expect(router.handle({ type: 'settings.save', serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 1 }))
    .resolves.toEqual({ ok: true, data: null });
  expect(saveServerUrl).toHaveBeenCalledWith('https://vault.example.com');
  expect(saveDefaultUriMatchStrategy).toHaveBeenCalledWith(1);
});
```

- [ ] **Step 6: Update options UI**

In `src/ui/options/options.html`, add a select before the Save button:

```html
<label for="defaultUriMatchStrategy">Default URI match strategy</label>
<select id="defaultUriMatchStrategy">
  <option value="0">Base domain / Domain</option>
  <option value="1">Host</option>
  <option value="2">Starts with</option>
  <option value="3">Exact</option>
  <option value="4">Regular expression</option>
  <option value="5">Never</option>
</select>
```

In `src/ui/options/options.ts`, import `isUriMatchStrategySetting`:

```ts
import { isUriMatchStrategySetting } from '../../core/vault/uri-match.js';
```

Add:

```ts
const defaultUriMatchStrategyInput = document.getElementById('defaultUriMatchStrategy') as HTMLSelectElement;
```

In `init()`, set:

```ts
const { serverUrl, defaultUriMatchStrategy } = response.data as { serverUrl?: string; defaultUriMatchStrategy: number };
if (serverUrl) input.value = serverUrl;
defaultUriMatchStrategyInput.value = String(defaultUriMatchStrategy);
```

In submit handler, before sending:

```ts
const parsedStrategy = Number(defaultUriMatchStrategyInput.value);
if (!isUriMatchStrategySetting(parsedStrategy)) {
  setStatus('Unsupported URI match strategy.', true);
  return;
}
```

Send:

```ts
const response = await sendRequest({ type: 'settings.save', serverUrl: normalized, defaultUriMatchStrategy: parsedStrategy });
```

- [ ] **Step 7: Run focused tests and typecheck**

Run:

```powershell
npm.cmd test -- src/background/settings.test.ts src/background/router.test.ts
npm.cmd run typecheck
```

Expected: tests PASS and typecheck exits 0.

- [ ] **Step 8: Commit**

Run:

```powershell
git add src/background/settings.ts src/background/settings.test.ts src/background/router.ts src/background/router.test.ts src/messaging/protocol.ts src/ui/options/options.html src/ui/options/options.ts
git commit -m "feat: add autofill match strategy setting" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: Typed Autofill Errors and Protocol

**Files:**
- Create: `src/core/errors.ts`
- Modify: `src/messaging/protocol.ts`
- Modify: `src/background/router.ts`
- Modify: `src/background/router.test.ts`

**Interfaces:**
- Produces:
  - `AppErrorCode = 'error' | 'locked' | 'sync_required' | 'no_match' | 'stale_form' | 'denied'`
  - `AppError`
  - `AutofillCandidate`
  - `AutofillCredentials`
  - Request messages: `autofill.findCandidates`, `autofill.getCredentials`
- Consumes: `UriMatchStrategySetting`.

- [ ] **Step 1: Write failing router error test**

In `src/background/router.test.ts`, add:

```ts
import { AppError } from '../core/errors.js';
```

Add test:

```ts
it('preserves typed application error codes', async () => {
  const router = createRouter({
    auth: { lock: vi.fn(async () => { throw new AppError('locked', 'Vault is locked'); }) },
    vault: {},
    settings: {
      getServerUrl: vi.fn(),
      saveServerUrl: vi.fn(),
      getDefaultUriMatchStrategy: vi.fn(async () => 0),
      saveDefaultUriMatchStrategy: vi.fn(),
    },
  });
  await expect(router.handle({ type: 'auth.lock' }))
    .resolves.toEqual({ ok: false, error: { code: 'locked', message: 'Vault is locked' } });
});
```

- [ ] **Step 2: Run router test to verify failure**

Run:

```powershell
npm.cmd test -- src/background/router.test.ts
```

Expected: FAIL because `src/core/errors.ts` does not exist.

- [ ] **Step 3: Add typed error class**

Create `src/core/errors.ts`:

```ts
export type AppErrorCode =
  | 'error'
  | 'locked'
  | 'sync_required'
  | 'no_match'
  | 'stale_form'
  | 'denied';

export class AppError extends Error {
  constructor(
    readonly code: AppErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'AppError';
  }
}
```

- [ ] **Step 4: Update protocol types**

In `src/messaging/protocol.ts`, import:

```ts
import type { AppErrorCode } from '../core/errors.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
```

Add exported interfaces:

```ts
export interface AutofillCandidate {
  id: string;
  name: string;
  username?: string;
  matchedUri: string;
  matchType: UriMatchStrategySetting;
  favorite: boolean;
}

export interface AutofillCredentials {
  username?: string;
  password?: string;
}
```

Add request union members:

```ts
| { type: 'autofill.findCandidates'; frameUrl: string; formSignature?: string }
| { type: 'autofill.getCredentials'; cipherId: string; frameUrl: string }
```

Add response union members:

```ts
| { ok: true; data: AutofillCandidate[] }
| { ok: true; data: AutofillCredentials }
```

Change the error response to:

```ts
| { ok: false; error: { code: AppErrorCode; message: string } };
```

- [ ] **Step 5: Preserve AppError code in router**

In `src/background/router.ts`, import:

```ts
import { AppError } from '../core/errors.js';
```

Replace catch body:

```ts
} catch (err) {
  if (err instanceof AppError) {
    return { ok: false, error: { code: err.code, message: err.message } };
  }
  return { ok: false, error: { code: 'error', message: err instanceof Error ? err.message : String(err) } };
}
```

- [ ] **Step 6: Run focused tests**

Run:

```powershell
npm.cmd test -- src/background/router.test.ts
npm.cmd run typecheck
```

Expected: router tests PASS and typecheck exits 0.

- [ ] **Step 7: Commit**

Run:

```powershell
git add src/core/errors.ts src/messaging/protocol.ts src/background/router.ts src/background/router.test.ts
git commit -m "feat: add typed autofill protocol errors" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 5: VaultService Autofill APIs

**Files:**
- Modify: `src/core/vault/vault-service.ts`
- Modify: `src/core/vault/vault-service.test.ts`

**Interfaces:**
- Consumes:
  - `LoginUri`, `UriMatchStrategySetting`, `matchLoginUri`, `compareMatchResults`
  - `AppError`
  - `AutofillCandidate`, `AutofillCredentials`
- Produces:
  - `VaultService.findAutofillCandidates(frameUrl: string, defaultStrategy: UriMatchStrategySetting): Promise<AutofillCandidate[]>`
  - `VaultService.getAutofillCredentials(cipherId: string, frameUrl: string, defaultStrategy: UriMatchStrategySetting): Promise<AutofillCredentials>`

- [ ] **Step 1: Write failing candidate tests**

In `src/core/vault/vault-service.test.ts`, add imports:

```ts
import { UriMatchStrategy } from './uri-match.js';
```

Update `makeService()` to return the session manager for locked-state tests:

```ts
return { service: new VaultService({ api, auth, session: sm, localStore }), api, session: sm };
```

Add helper encrypted sync response with two ciphers by using existing `makeSync()` shape and `FIELD_VECTOR.encString`. For a direct readable test, add this test after existing sync tests:

```ts
it('findAutofillCandidates returns sorted matching summaries without passwords', async () => {
  const sync = makeSync();
  sync.ciphers[0]!.id = 'domain';
  sync.ciphers[0]!.favorite = false;
  sync.ciphers[0]!.login = {
    username: FIELD_VECTOR.encString,
    password: FIELD_VECTOR.encString,
    uris: [{ uri: FIELD_VECTOR.encString, match: UriMatchStrategy.Domain }],
  };
  const { service } = await makeService(sync);
  await service.sync();

  const candidates = await service.findAutofillCandidates(FIELD_VECTOR.plaintext, UriMatchStrategy.Domain);

  expect(candidates).toEqual([{
    id: 'domain',
    name: FIELD_VECTOR.plaintext,
    username: FIELD_VECTOR.plaintext,
    matchedUri: FIELD_VECTOR.plaintext,
    matchType: UriMatchStrategy.Domain,
    favorite: false,
  }]);
  expect(JSON.stringify(candidates)).not.toContain('password');
});
```

Add locked/sync tests:

```ts
it('findAutofillCandidates rejects when vault is locked', async () => {
  const { service } = await makeService();
  await expect(service.findAutofillCandidates('https://example.com', UriMatchStrategy.Domain))
    .rejects.toMatchObject({ code: 'sync_required' });
});
```

This expects `sync_required` because no summaries exist before sync. A locked case is covered after clearing session key:

```ts
it('findAutofillCandidates rejects locked when summaries exist but user key is unavailable', async () => {
  const { service, session } = await makeService();
  await service.sync();
  await session.lock();
  await expect(service.findAutofillCandidates(FIELD_VECTOR.plaintext, UriMatchStrategy.Domain))
    .rejects.toMatchObject({ code: 'locked' });
});
```

- [ ] **Step 2: Write failing credential tests**

Add:

```ts
it('getAutofillCredentials re-checks URI match before decrypting credentials', async () => {
  const { service } = await makeService();
  await service.sync();

  await expect(service.getAutofillCredentials('cipher-1', FIELD_VECTOR.plaintext, UriMatchStrategy.Domain))
    .resolves.toEqual({ username: FIELD_VECTOR.plaintext, password: FIELD_VECTOR.plaintext });

  await expect(service.getAutofillCredentials('cipher-1', 'https://not-matching.example.org', UriMatchStrategy.Domain))
    .rejects.toMatchObject({ code: 'denied' });
});
```

- [ ] **Step 3: Run vault-service test to verify failure**

Run:

```powershell
npm.cmd test -- src/core/vault/vault-service.test.ts
```

Expected: FAIL because methods do not exist.

- [ ] **Step 4: Implement VaultService autofill methods**

In `src/core/vault/vault-service.ts`, import:

```ts
import { AppError } from '../errors.js';
import type { AutofillCandidate, AutofillCredentials } from '../../messaging/protocol.js';
import { compareMatchResults, matchLoginUri, type UriMatchResult, type UriMatchStrategySetting } from './uri-match.js';
```

Add methods inside `VaultService`:

```ts
async findAutofillCandidates(
  frameUrl: string,
  defaultStrategy: UriMatchStrategySetting,
): Promise<AutofillCandidate[]> {
  const summaries = await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY);
  if (!summaries) throw new AppError('sync_required', 'Sync required');
  const userKey = await this.deps.session.loadUserKey();
  if (!userKey) throw new AppError('locked', 'Vault is locked');

  const candidates = summaries
    .filter((item) => item.type === 1 && !item.undecryptable)
    .flatMap((item) => {
      const best = bestMatch(item.loginUris, frameUrl, defaultStrategy);
      if (!best) return [];
      const candidate: AutofillCandidate = {
        id: item.id,
        name: item.name,
        matchedUri: best.matchedUri,
        matchType: best.matchType,
        favorite: item.favorite,
      };
      if (item.username) candidate.username = item.username;
      return [candidate];
    });

  candidates.sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    const score = matchScore(a.matchType) - matchScore(b.matchType);
    if (score !== 0) return score;
    const name = a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    if (name !== 0) return name;
    return (a.username ?? '').localeCompare(b.username ?? '', undefined, { sensitivity: 'base' });
  });
  return candidates;
}

async getAutofillCredentials(
  cipherId: string,
  frameUrl: string,
  defaultStrategy: UriMatchStrategySetting,
): Promise<AutofillCredentials> {
  const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
  if (!cache) throw new AppError('sync_required', 'Sync required');
  const userKey = await this.deps.session.loadUserKey();
  if (!userKey) throw new AppError('locked', 'Vault is locked');
  const cipher = cache.ciphers.find((c) => c.id === cipherId);
  if (!cipher) throw new AppError('denied', 'Autofill item is not allowed for this page');
  const decrypted = await decryptCipher(cipher, userKey);
  if (!decrypted || decrypted.undecryptable || !bestMatch(decrypted.loginUris, frameUrl, defaultStrategy)) {
    throw new AppError('denied', 'Autofill item is not allowed for this page');
  }
  const out: AutofillCredentials = {};
  if (decrypted.username) out.username = decrypted.username;
  if (decrypted.password) out.password = decrypted.password;
  return out;
}
```

Add helper functions below the class:

```ts
function bestMatch(
  loginUris: CipherSummary['loginUris'],
  frameUrl: string,
  defaultStrategy: UriMatchStrategySetting,
): UriMatchResult | undefined {
  return loginUris
    .map((uri) => matchLoginUri(uri, frameUrl, defaultStrategy))
    .filter((match): match is UriMatchResult => Boolean(match))
    .sort(compareMatchResults)[0];
}

function matchScore(matchType: UriMatchStrategySetting): number {
  const match = matchLoginUri({ uri: 'https://example.com', match: matchType }, 'https://example.com', matchType);
  return match?.score ?? 99;
}
```

- [ ] **Step 5: Run focused tests**

Run:

```powershell
npm.cmd test -- src/core/vault/vault-service.test.ts
npm.cmd run typecheck
```

Expected: tests PASS and typecheck exits 0.

- [ ] **Step 6: Commit**

Run:

```powershell
git add src/core/vault/vault-service.ts src/core/vault/vault-service.test.ts
git commit -m "feat: add worker-side autofill vault APIs" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 6: Router Autofill Wiring

**Files:**
- Modify: `src/background/router.ts`
- Modify: `src/background/router.test.ts`

**Interfaces:**
- Consumes:
  - `VaultService.findAutofillCandidates(frameUrl, defaultStrategy)`
  - `VaultService.getAutofillCredentials(cipherId, frameUrl, defaultStrategy)`
  - `settings.getDefaultUriMatchStrategy()`
- Produces:
  - Routed `autofill.findCandidates`
  - Routed `autofill.getCredentials`

- [ ] **Step 1: Write failing router tests**

In `src/background/router.test.ts`, add:

```ts
it('routes autofill.findCandidates through settings default strategy', async () => {
  const findAutofillCandidates = vi.fn(async () => [{
    id: '1',
    name: 'Example',
    username: 'me@example.com',
    matchedUri: 'https://example.com',
    matchType: 0 as const,
    favorite: false,
  }]);
  const router = createRouter({
    auth: {},
    vault: { findAutofillCandidates },
    settings: {
      getServerUrl: vi.fn(),
      saveServerUrl: vi.fn(),
      getDefaultUriMatchStrategy: vi.fn(async () => 0),
      saveDefaultUriMatchStrategy: vi.fn(),
    },
  });
  await expect(router.handle({ type: 'autofill.findCandidates', frameUrl: 'https://example.com/login' }))
    .resolves.toEqual({ ok: true, data: [{
      id: '1',
      name: 'Example',
      username: 'me@example.com',
      matchedUri: 'https://example.com',
      matchType: 0,
      favorite: false,
    }] });
  expect(findAutofillCandidates).toHaveBeenCalledWith('https://example.com/login', 0);
});

it('routes autofill.getCredentials through settings default strategy', async () => {
  const getAutofillCredentials = vi.fn(async () => ({ username: 'me@example.com', password: 'secret' }));
  const router = createRouter({
    auth: {},
    vault: { getAutofillCredentials },
    settings: {
      getServerUrl: vi.fn(),
      saveServerUrl: vi.fn(),
      getDefaultUriMatchStrategy: vi.fn(async () => 1),
      saveDefaultUriMatchStrategy: vi.fn(),
    },
  });
  await expect(router.handle({ type: 'autofill.getCredentials', cipherId: '1', frameUrl: 'https://example.com/login' }))
    .resolves.toEqual({ ok: true, data: { username: 'me@example.com', password: 'secret' } });
  expect(getAutofillCredentials).toHaveBeenCalledWith('1', 'https://example.com/login', 1);
});
```

- [ ] **Step 2: Run router tests to verify failure**

Run:

```powershell
npm.cmd test -- src/background/router.test.ts
```

Expected: FAIL because router lacks `autofill.*` branches.

- [ ] **Step 3: Add router branches**

In `src/background/router.ts`, add switch cases before `settings.get`:

```ts
case 'autofill.findCandidates': {
  if (!deps.vault.findAutofillCandidates) throw new Error('vault.findAutofillCandidates is not wired');
  const defaultStrategy = await deps.settings.getDefaultUriMatchStrategy();
  return { ok: true, data: await deps.vault.findAutofillCandidates(request.frameUrl, defaultStrategy) };
}
case 'autofill.getCredentials': {
  if (!deps.vault.getAutofillCredentials) throw new Error('vault.getAutofillCredentials is not wired');
  const defaultStrategy = await deps.settings.getDefaultUriMatchStrategy();
  return { ok: true, data: await deps.vault.getAutofillCredentials(request.cipherId, request.frameUrl, defaultStrategy) };
}
```

- [ ] **Step 4: Run focused tests**

Run:

```powershell
npm.cmd test -- src/background/router.test.ts
npm.cmd run typecheck
```

Expected: router tests PASS and typecheck exits 0.

- [ ] **Step 5: Commit**

Run:

```powershell
git add src/background/router.ts src/background/router.test.ts
git commit -m "feat: route autofill worker messages" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 7: Content Form Detection and Filling

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `src/content/form-detection.ts`
- Create: `src/content/form-detection.test.ts`
- Create: `src/content/fill.ts`
- Create: `src/content/fill.test.ts`

**Interfaces:**
- Produces:
  - `DetectedLoginForm`
  - `detectLoginForms(root?: ParentNode): DetectedLoginForm[]`
  - `isFillableInput(input: HTMLInputElement): boolean`
  - `fillLoginForm(form: DetectedLoginForm, credentials: AutofillCredentials): boolean`
- Consumes: `AutofillCredentials`.

- [ ] **Step 1: Install DOM test dependency**

Run:

```powershell
npm.cmd install -D happy-dom@latest
```

Expected: `happy-dom` appears in `devDependencies`.

- [ ] **Step 2: Write failing form detection tests**

Create `src/content/form-detection.test.ts`:

```ts
// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { detectLoginForms, isFillableInput } from './form-detection.js';

describe('form detection', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  it('detects a visible login form with username and password fields', () => {
    document.body.innerHTML = `
      <form>
        <input type="email" autocomplete="username" value="">
        <input type="password" autocomplete="current-password" value="">
      </form>
    `;

    const forms = detectLoginForms();

    expect(forms).toHaveLength(1);
    expect(forms[0]?.usernameInput?.type).toBe('email');
    expect(forms[0]?.passwordInput.type).toBe('password');
  });

  it('ignores hidden, disabled, and readonly password fields', () => {
    document.body.innerHTML = `
      <input type="password" hidden>
      <input type="password" disabled>
      <input type="password" readonly>
    `;

    expect(detectLoginForms()).toEqual([]);
  });

  it('uses a nearby username field when inputs are not inside a form element', () => {
    document.body.innerHTML = `
      <section>
        <input type="text" name="user">
        <div><input type="password" name="pass"></div>
      </section>
    `;

    const forms = detectLoginForms();

    expect(forms).toHaveLength(1);
    expect(forms[0]?.usernameInput?.name).toBe('user');
  });

  it('checks fillable input state directly', () => {
    const input = document.createElement('input');
    input.type = 'password';
    expect(isFillableInput(input)).toBe(true);
    input.readOnly = true;
    expect(isFillableInput(input)).toBe(false);
  });
});
```

- [ ] **Step 3: Run form detection tests to verify failure**

Run:

```powershell
npm.cmd test -- src/content/form-detection.test.ts
```

Expected: FAIL because `src/content/form-detection.ts` does not exist.

- [ ] **Step 4: Implement form detection**

Create `src/content/form-detection.ts`:

```ts
export interface DetectedLoginForm {
  id: string;
  form: HTMLFormElement | null;
  usernameInput?: HTMLInputElement;
  passwordInput: HTMLInputElement;
  anchor: HTMLElement;
}

let nextFormId = 0;

export function detectLoginForms(root: ParentNode = document): DetectedLoginForm[] {
  const passwords = Array.from(root.querySelectorAll<HTMLInputElement>('input[type="password"]'))
    .filter(isFillableInput);

  return passwords.map((passwordInput) => {
    const form = passwordInput.form;
    const container = form ?? nearestContainer(passwordInput);
    const usernameInput = findUsernameInput(container, passwordInput);
    return {
      id: passwordInput.dataset.vwAutofillId ?? assignFormId(passwordInput),
      form,
      usernameInput,
      passwordInput,
      anchor: passwordInput,
    };
  });
}

export function isFillableInput(input: HTMLInputElement): boolean {
  const editable = input.type !== 'hidden' && !input.hidden && !input.disabled && !input.readOnly;
  if (!editable) return false;
  if (input.offsetParent !== null) return true;
  return isHappyDomVisible(input);
}

function assignFormId(input: HTMLInputElement): string {
  const id = `vw-form-${nextFormId++}`;
  input.dataset.vwAutofillId = id;
  return id;
}

function nearestContainer(input: HTMLInputElement): ParentNode {
  return input.closest('form, section, main, div') ?? document;
}

function findUsernameInput(container: ParentNode, passwordInput: HTMLInputElement): HTMLInputElement | undefined {
  const candidates = Array.from(container.querySelectorAll<HTMLInputElement>('input'))
    .filter((input) => input !== passwordInput)
    .filter(isFillableInput)
    .filter((input) => ['email', 'text', 'search', 'tel', 'url'].includes(input.type))
    .filter((input) => {
      const hint = `${input.name} ${input.id} ${input.autocomplete} ${input.getAttribute('aria-label') ?? ''}`.toLowerCase();
      return hint.includes('user') || hint.includes('email') || hint.includes('login') || input.type === 'email';
    });
  return candidates.at(-1);
}

function isHappyDomVisible(input: HTMLInputElement): boolean {
  const style = input.ownerDocument.defaultView?.getComputedStyle(input);
  return input.isConnected && style?.display !== 'none' && style?.visibility !== 'hidden';
}
```

- [ ] **Step 5: Write failing fill tests**

Create `src/content/fill.test.ts`:

```ts
// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { detectLoginForms } from './form-detection.js';
import { fillLoginForm } from './fill.js';

describe('fillLoginForm', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  it('fills username and password and dispatches input/change events', () => {
    document.body.innerHTML = `
      <form>
        <input id="user" type="email">
        <input id="pass" type="password">
      </form>
    `;
    const user = document.getElementById('user') as HTMLInputElement;
    const pass = document.getElementById('pass') as HTMLInputElement;
    const userInput = vi.fn();
    const passChange = vi.fn();
    user.addEventListener('input', userInput);
    pass.addEventListener('change', passChange);

    const form = detectLoginForms()[0]!;
    expect(fillLoginForm(form, { username: 'me@example.com', password: 'secret' })).toBe(true);

    expect(user.value).toBe('me@example.com');
    expect(pass.value).toBe('secret');
    expect(userInput).toHaveBeenCalledTimes(1);
    expect(passChange).toHaveBeenCalledTimes(1);
  });

  it('does not fill disabled or readonly fields', () => {
    document.body.innerHTML = `
      <form>
        <input id="user" type="email" readonly>
        <input id="pass" type="password" disabled>
      </form>
    `;
    expect(detectLoginForms()).toEqual([]);
  });
});
```

- [ ] **Step 6: Run fill tests to verify failure**

Run:

```powershell
npm.cmd test -- src/content/fill.test.ts
```

Expected: FAIL because `src/content/fill.ts` does not exist.

- [ ] **Step 7: Implement fill module**

Create `src/content/fill.ts`:

```ts
import type { AutofillCredentials } from '../messaging/protocol.js';
import type { DetectedLoginForm } from './form-detection.js';
import { isFillableInput } from './form-detection.js';

export function fillLoginForm(form: DetectedLoginForm, credentials: AutofillCredentials): boolean {
  let filled = false;
  if (credentials.username && form.usernameInput && isFillableInput(form.usernameInput)) {
    setInputValue(form.usernameInput, credentials.username);
    filled = true;
  }
  if (credentials.password && isFillableInput(form.passwordInput)) {
    setInputValue(form.passwordInput, credentials.password);
    filled = true;
  }
  return filled;
}

function setInputValue(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}
```

- [ ] **Step 8: Run focused tests**

Run:

```powershell
npm.cmd test -- src/content/form-detection.test.ts src/content/fill.test.ts
npm.cmd run typecheck
```

Expected: tests PASS and typecheck exits 0.

- [ ] **Step 9: Commit**

Run:

```powershell
git add package.json package-lock.json src/content/form-detection.ts src/content/form-detection.test.ts src/content/fill.ts src/content/fill.test.ts
git commit -m "feat: detect and fill login forms" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 8: Content Popover, Controller, Manifest, and Build

**Files:**
- Create: `src/content/popover.ts`
- Create: `src/content/popover.test.ts`
- Create: `src/content/autofill.ts`
- Create: `src/content/autofill.test.ts`
- Modify: `src/manifest.json`
- Modify: `src/manifest.test.ts`
- Modify: `build.mjs`

**Interfaces:**
- Consumes:
  - `detectLoginForms`
  - `fillLoginForm`
  - `sendRequest`
  - `AutofillCandidate`
  - `AutofillCredentials`
- Produces:
  - Shadow-DOM anchored popover.
  - Content script entry `content/autofill.js`.
  - Manifest `content_scripts` with `matches: ["http://*/*", "https://*/*"]` and `all_frames: true`.

- [ ] **Step 1: Write failing popover tests**

Create `src/content/popover.test.ts`:

```ts
// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createAutofillPopover } from './popover.js';

describe('autofill popover', () => {
  beforeEach(() => {
    document.body.innerHTML = '<input id="pass" type="password">';
  });

  it('renders status text in shadow DOM', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showStatus('Locked');
    expect(popover.element.shadowRoot?.textContent).toContain('Locked');
  });

  it('renders candidates and calls onSelect when clicked', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onSelect = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect });
    popover.showCandidates([{
      id: '1',
      name: 'Example',
      username: 'me@example.com',
      matchedUri: 'https://example.com',
      matchType: 0,
      favorite: false,
    }]);

    popover.element.shadowRoot?.querySelector<HTMLButtonElement>('[data-cipher-id="1"]')?.click();

    expect(onSelect).toHaveBeenCalledWith('1');
    expect(popover.element.shadowRoot?.textContent).not.toContain('secret');
  });
});
```

- [ ] **Step 2: Run popover tests to verify failure**

Run:

```powershell
npm.cmd test -- src/content/popover.test.ts
```

Expected: FAIL because `src/content/popover.ts` does not exist.

- [ ] **Step 3: Implement popover**

Create `src/content/popover.ts`:

```ts
import type { AutofillCandidate } from '../messaging/protocol.js';

export interface AutofillPopover {
  element: HTMLElement;
  showStatus(message: string): void;
  showCandidates(candidates: AutofillCandidate[]): void;
  remove(): void;
}

export interface AutofillPopoverOptions {
  anchor: HTMLElement;
  onOpen(): void;
  onSelect(cipherId: string): void;
}

export function createAutofillPopover(options: AutofillPopoverOptions): AutofillPopover {
  const host = document.createElement('div');
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';
  const shadow = host.attachShadow({ mode: 'open' });
  document.documentElement.append(host);
  positionNearAnchor(host, options.anchor);

  const render = (body: string) => {
    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        .box { font: 13px system-ui, sans-serif; color: #24292f; background: #fff; border: 1px solid #d0d7de; border-radius: 10px; box-shadow: 0 8px 24px rgba(140,149,159,.25); min-width: 220px; max-width: 320px; padding: 8px; }
        button { font: inherit; width: 100%; text-align: left; border: 0; background: transparent; padding: 8px; border-radius: 8px; cursor: pointer; }
        button:hover { background: #f6f8fa; }
        .muted { color: #57606a; font-size: 12px; }
      </style>
      <div class="box">${body}</div>
    `;
  };

  render('<button id="open" type="button">Vaultwarden</button>');
  shadow.getElementById('open')?.addEventListener('click', options.onOpen);

  return {
    element: host,
    showStatus(message: string) {
      render(`<div>${escapeHtml(message)}</div>`);
    },
    showCandidates(candidates: AutofillCandidate[]) {
      if (candidates.length === 0) {
        render('<div>No matching logins</div>');
        return;
      }
      render(candidates.map((candidate) => `
        <button type="button" data-cipher-id="${escapeHtml(candidate.id)}">
          <strong>${escapeHtml(candidate.name)}</strong>
          <div class="muted">${escapeHtml(candidate.username ?? '')}</div>
          <div class="muted">${escapeHtml(candidate.matchedUri)}</div>
        </button>
      `).join(''));
      shadow.querySelectorAll<HTMLButtonElement>('button[data-cipher-id]').forEach((button) => {
        button.addEventListener('click', () => options.onSelect(button.dataset.cipherId!));
      });
    },
    remove() {
      host.remove();
    },
  };
}

function positionNearAnchor(host: HTMLElement, anchor: HTMLElement): void {
  const rect = anchor.getBoundingClientRect();
  host.style.left = `${Math.max(8, rect.left + window.scrollX)}px`;
  host.style.top = `${Math.max(8, rect.bottom + window.scrollY + 4)}px`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
```

- [ ] **Step 4: Write failing controller and manifest tests**

Create `src/content/autofill.test.ts`:

```ts
// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../messaging/protocol.js', () => ({
  sendRequest: vi.fn(),
}));

import { sendRequest } from '../messaging/protocol.js';
import { startAutofill } from './autofill.js';

describe('autofill controller', () => {
  beforeEach(() => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    vi.mocked(sendRequest).mockReset();
  });

  it('requests candidates for the current frame URL when popover opens', async () => {
    vi.mocked(sendRequest).mockResolvedValue({ ok: true, data: [] });

    startAutofill('https://example.com/login');
    document.querySelector<HTMLElement>('div')?.shadowRoot?.querySelector<HTMLButtonElement>('#open')?.click();
    await Promise.resolve();

    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.findCandidates', frameUrl: 'https://example.com/login' });
  });
});
```

Create or modify `src/manifest.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import manifest from './manifest.json';

describe('manifest', () => {
  it('registers autofill content script for http and https in all frames', () => {
    expect(manifest.content_scripts).toEqual([{
      matches: ['http://*/*', 'https://*/*'],
      js: ['content/autofill.js'],
      run_at: 'document_idle',
      all_frames: true,
    }]);
  });
});
```

- [ ] **Step 5: Run controller and manifest tests to verify failure**

Run:

```powershell
npm.cmd test -- src/content/autofill.test.ts src/manifest.test.ts
```

Expected: FAIL because `autofill.ts` and manifest content script are missing.

- [ ] **Step 6: Implement content controller**

Create `src/content/autofill.ts`:

```ts
import { sendRequest } from '../messaging/protocol.js';
import { fillLoginForm } from './fill.js';
import { detectLoginForms, type DetectedLoginForm } from './form-detection.js';
import { createAutofillPopover } from './popover.js';

export function startAutofill(frameUrl = window.location.href): void {
  if (!frameUrl.startsWith('http://') && !frameUrl.startsWith('https://')) return;
  const attach = () => attachPopovers(frameUrl);
  attach();
  const observer = new MutationObserver(debounce(attach, 250));
  observer.observe(document.documentElement, { childList: true, subtree: true });
}

function attachPopovers(frameUrl: string): void {
  for (const form of detectLoginForms()) {
    if (document.querySelector(`[data-vw-popover-for="${form.id}"]`)) continue;
    attachPopover(frameUrl, form);
  }
}

function attachPopover(frameUrl: string, form: DetectedLoginForm): void {
  const popover = createAutofillPopover({
    anchor: form.anchor,
    onOpen: () => {
      void loadCandidates(frameUrl, popover);
    },
    onSelect: (cipherId) => {
      void fillSelected(frameUrl, form, cipherId, popover);
    },
  });
  popover.element.dataset.vwPopoverFor = form.id;
}

async function loadCandidates(frameUrl: string, popover: ReturnType<typeof createAutofillPopover>): Promise<void> {
  const response = await sendRequest({ type: 'autofill.findCandidates', frameUrl });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (Array.isArray(response.data)) popover.showCandidates(response.data);
}

async function fillSelected(
  frameUrl: string,
  form: DetectedLoginForm,
  cipherId: string,
  popover: ReturnType<typeof createAutofillPopover>,
): Promise<void> {
  if (!form.passwordInput.isConnected || (form.usernameInput && !form.usernameInput.isConnected)) {
    popover.showStatus('Form is no longer available');
    return;
  }
  const response = await sendRequest({ type: 'autofill.getCredentials', cipherId, frameUrl });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  const filled = fillLoginForm(form, response.data);
  popover.showStatus(filled ? 'Filled' : 'No fillable fields');
}

function messageForError(code: string, fallback: string): string {
  switch (code) {
    case 'locked':
      return 'Vault is locked';
    case 'sync_required':
      return 'Sync required';
    case 'no_match':
      return 'No matching logins';
    case 'denied':
      return 'Autofill denied for this page';
    default:
      return fallback;
  }
}

function debounce(fn: () => void, ms: number): () => void {
  let timer: number | undefined;
  return () => {
    if (timer !== undefined) window.clearTimeout(timer);
    timer = window.setTimeout(fn, ms);
  };
}

startAutofill();
```

- [ ] **Step 7: Update manifest and build**

In `src/manifest.json`, add:

```json
"content_scripts": [
  {
    "matches": ["http://*/*", "https://*/*"],
    "js": ["content/autofill.js"],
    "run_at": "document_idle",
    "all_frames": true
  }
],
```

In `build.mjs`, add entry point:

```js
'content/autofill': 'src/content/autofill.ts',
```

- [ ] **Step 8: Run focused tests and build**

Run:

```powershell
npm.cmd test -- src/content/popover.test.ts src/content/autofill.test.ts src/manifest.test.ts
npm.cmd run typecheck
npm.cmd run build
```

Expected: tests PASS, typecheck exits 0, build emits `dist\content\autofill.js`.

- [ ] **Step 9: Commit**

Run:

```powershell
git add src/content/popover.ts src/content/popover.test.ts src/content/autofill.ts src/content/autofill.test.ts src/manifest.json src/manifest.test.ts build.mjs
git commit -m "feat: add autofill content script UI" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 9: Documentation and Final Verification

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: all M4 behavior.
- Produces: README acceptance steps for M4.

- [ ] **Step 1: Update README scope**

In `README.md`, add M4 to the Scope section:

```md
M4 adds:

- Native content-script autofill on `http://*/*` and `https://*/*` pages, including all frames.
- Bitwarden-like URI match strategies: Domain, Host, Starts With, Exact, Regular Expression, and Never.
- Semi-automatic form-side popover: credentials are filled only after user selection and forms are never auto-submitted.
```

- [ ] **Step 2: Update manual acceptance**

Append these steps to the Manual acceptance list:

```md
13. Confirm Options exposes the default URI match strategy and defaults to Base domain / Domain.
14. Open a website with one matching login item and confirm the Vaultwarden popover appears near the password field.
15. Click the matching login item and confirm username/password fill without submitting the form.
16. Open a website with multiple matching login items and confirm favorites and stronger match types are listed first.
17. Open a website with no matching login item and confirm the popover reports no matching logins.
18. Lock the vault, reload a login page, and confirm the popover reports locked without showing or filling credentials.
19. Test an iframe login page and confirm matching uses the iframe URL, not the top-level page URL.
20. Confirm hidden, disabled, and readonly fields are not filled.
```

- [ ] **Step 3: Run full verification**

Run:

```powershell
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build
git status --short
```

Expected:

```text
Test Files ... passed
Tests ... passed
tsc --noEmit exits 0
eslint . exits 0
build done
git status --short shows only README.md before commit
```

- [ ] **Step 4: Commit**

Run:

```powershell
git add README.md
git commit -m "docs: add m4 autofill acceptance steps" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

- [ ] **Step 5: Final status**

Run:

```powershell
git status --short
git --no-pager log --oneline -5
```

Expected: clean worktree and latest commits include Tasks 5-9.

---

## Self-Review

**Spec coverage:** Task 1 implements public-suffix-aware Domain/Host/StartsWith/Exact/RegularExpression/Never matching. Task 2 preserves URI match metadata. Task 3 adds configurable default strategy. Tasks 4-6 add worker-gated typed messages, candidate lookup, credential retrieval, and second URI authorization. Tasks 7-8 add all-frame content script detection, popover UX, one-click fill, no hidden/disabled/readonly fills, and manifest/build wiring. Task 9 documents manual acceptance.

**Red-flag scan:** The plan avoids unresolved markers and gives concrete file paths, code, commands, expected failures, expected passes, and commit commands.

**Type consistency:** `UriMatchStrategySetting`, `LoginUri`, `AutofillCandidate`, `AutofillCredentials`, `AppError`, `findAutofillCandidates`, and `getAutofillCredentials` are introduced before use by subsequent tasks.
