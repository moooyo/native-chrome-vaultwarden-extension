# Idle Auto-Lock Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 1-minute `lastActivity` polling auto-lock with `chrome.idle`-based detection, add a lock/logout action setting applied on idle AND system-lock, and move clipboard auto-clear to a background offscreen document with a configurable duration.

**Architecture:** Two new pure, dependency-injected background modules (`idle-lock.ts`, `clipboard.ts`) hold the logic and are unit-tested with fakes; `background/index.ts` wires them to `browser.idle`, `chrome.offscreen`, alarms, and the message bus. A new offscreen document performs the actual clipboard clear. New settings travel on a dedicated `settings.saveSecurity` message decoupled from the serverUrl/host-permission form.

**Tech Stack:** TypeScript, MV3 (`webextension-polyfill` for `browser.*`; `chrome.offscreen`/`chrome.runtime.getContexts` via a narrow cast since they are untyped), vitest (+ happy-dom for DOM tests), esbuild build.

## Global Constraints

- **Idempotency:** `applyAction` MUST no-op when the vault is not unlocked (`isUnlocked()` guard) — the idle `onStateChanged` and the backstop alarm can both fire for one idle span; without the guard, `logout` cascades through multiple accounts.
- **Enabled gate:** idle handling (idle AND locked) is active ONLY when a numeric timeout is set (`idleSeconds !== null`). `never`/`onClose` disable both idle-timeout and system-lock response. The `idleSeconds===null` early-return in `applyAction` is the sole guard that ignores `'locked'` — the large sentinel detection interval only makes `'idle'` rare and has NO effect on `'locked'`.
- **Clipboard clear mechanism (MV3):** `document.execCommand('copy')` on an EMPTY selection is a no-op and does NOT clear the clipboard. The offscreen clearer uses `navigator.clipboard.writeText('')` first; on failure it overwrites with a single space via a `<textarea>` + `execCommand('copy')` (non-empty → works). Unconditional; never holds/persists the copied plaintext.
- **SW message guard:** the SW `onMessage` listener MUST synchronously `return;` (no Promise) for messages it does not own (type starting `offscreen.`), so the offscreen document's response is not hijacked.
- **Settings decoupling:** new settings travel on `settings.saveSecurity` (onIdleAction + clipboardClearSeconds only) — NOT the serverUrl `settings.save` form (which forces a valid serverUrl + `permissions.request`).
- **Clipboard options are ≥30s** (`'never' | 30 | 60 | 120 | 300`, default `'60'`); Chrome clamps alarms to ~30s so sub-30s is not offered. Background clear timing is best-effort.
- **System-lock applies the configured action; if `logout` is selected the options UI shows a warning** that logout ends the session on every system lock / idle timeout.
- **Permissions added: exactly `"idle"` and `"offscreen"`.** No host-permission changes.
- **English UI copy.** No i18n.
- Spec: `docs/superpowers/specs/2026-07-01-idle-autolock-improvements-design.md`.

---

### Task 1: Settings — `onIdleAction` + `clipboardClearSeconds`

**Files:**
- Modify: `src/background/settings.ts`
- Test: `src/background/settings.test.ts`

**Interfaces:**
- Produces: `type OnIdleAction = 'lock' | 'logout'`; `DEFAULT_ON_IDLE_ACTION`; `isOnIdleAction`; `type ClipboardClearSetting = 'never'|'30'|'60'|'120'|'300'`; `DEFAULT_CLIPBOARD_CLEAR`; `isClipboardClearSetting`; `clipboardClearToSeconds(v): number|null`; service methods `getOnIdleAction`/`saveOnIdleAction`/`getClipboardClearSetting`/`saveClipboardClearSetting`/`getClipboardClearSeconds`.

- [ ] **Step 1: Write the failing tests**

Append to `src/background/settings.test.ts`:

```ts
import { isOnIdleAction, isClipboardClearSetting, clipboardClearToSeconds, DEFAULT_ON_IDLE_ACTION, DEFAULT_CLIPBOARD_CLEAR } from './settings.js';

describe('onIdleAction setting', () => {
  it('defaults to lock and round-trips lock/logout', async () => {
    const s = createSettingsService(createMemoryStore());
    expect(await s.getOnIdleAction()).toBe(DEFAULT_ON_IDLE_ACTION);
    expect(DEFAULT_ON_IDLE_ACTION).toBe('lock');
    await s.saveOnIdleAction('logout');
    expect(await s.getOnIdleAction()).toBe('logout');
  });
  it('rejects an unknown action and falls back on a corrupt stored value', async () => {
    const s = createSettingsService(createMemoryStore());
    await expect(s.saveOnIdleAction('sleep' as never)).rejects.toThrow();
    expect(isOnIdleAction('lock')).toBe(true);
    expect(isOnIdleAction('nope')).toBe(false);
  });
});

describe('clipboardClearSeconds setting', () => {
  it('defaults to 60 and round-trips values', async () => {
    const s = createSettingsService(createMemoryStore());
    expect(await s.getClipboardClearSetting()).toBe(DEFAULT_CLIPBOARD_CLEAR);
    expect(DEFAULT_CLIPBOARD_CLEAR).toBe('60');
    await s.saveClipboardClearSetting('never');
    expect(await s.getClipboardClearSetting()).toBe('never');
    expect(await s.getClipboardClearSeconds()).toBeNull();
    await s.saveClipboardClearSetting('120');
    expect(await s.getClipboardClearSeconds()).toBe(120);
  });
  it('validates values and maps never to null', () => {
    expect(isClipboardClearSetting('30')).toBe(true);
    expect(isClipboardClearSetting('15')).toBe(false);
    expect(clipboardClearToSeconds('never')).toBeNull();
    expect(clipboardClearToSeconds('300')).toBe(300);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/background/settings.test.ts`
Expected: FAIL — new exports/methods undefined.

- [ ] **Step 3: Add the settings**

In `src/background/settings.ts`, add near the top constants:

```ts
const ON_IDLE_ACTION_KEY = 'onIdleAction';
export type OnIdleAction = 'lock' | 'logout';
export const DEFAULT_ON_IDLE_ACTION: OnIdleAction = 'lock';
export function isOnIdleAction(value: unknown): value is OnIdleAction {
  return value === 'lock' || value === 'logout';
}

const CLIPBOARD_CLEAR_KEY = 'clipboardClearSeconds';
/** Clipboard auto-clear options. Seconds ≥30 (Chrome clamps alarms to ~30s) plus 'never'. */
export const CLIPBOARD_CLEAR_VALUES = ['never', '30', '60', '120', '300'] as const;
export type ClipboardClearSetting = (typeof CLIPBOARD_CLEAR_VALUES)[number];
export const DEFAULT_CLIPBOARD_CLEAR: ClipboardClearSetting = '60';
export function isClipboardClearSetting(value: unknown): value is ClipboardClearSetting {
  return typeof value === 'string' && (CLIPBOARD_CLEAR_VALUES as readonly string[]).includes(value);
}
/** Clear delay in seconds, or null when 'never'. */
export function clipboardClearToSeconds(value: ClipboardClearSetting): number | null {
  return value === 'never' ? null : Number(value);
}
```

Add to the `service` object (beside `getLockTimeout`/`saveLockTimeout`):

```ts
    async getOnIdleAction(): Promise<OnIdleAction> {
      const value = await store.get<unknown>(ON_IDLE_ACTION_KEY);
      return isOnIdleAction(value) ? value : DEFAULT_ON_IDLE_ACTION;
    },
    async saveOnIdleAction(value: OnIdleAction): Promise<void> {
      if (!isOnIdleAction(value)) throw new Error('unsupported idle action');
      await store.set(ON_IDLE_ACTION_KEY, value);
    },
    async getClipboardClearSetting(): Promise<ClipboardClearSetting> {
      const value = await store.get<unknown>(CLIPBOARD_CLEAR_KEY);
      return isClipboardClearSetting(value) ? value : DEFAULT_CLIPBOARD_CLEAR;
    },
    async saveClipboardClearSetting(value: ClipboardClearSetting): Promise<void> {
      if (!isClipboardClearSetting(value)) throw new Error('unsupported clipboard clear setting');
      await store.set(CLIPBOARD_CLEAR_KEY, value);
    },
    async getClipboardClearSeconds(): Promise<number | null> {
      return clipboardClearToSeconds(await service.getClipboardClearSetting());
    },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/background/settings.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/background/settings.ts src/background/settings.test.ts
git commit -m "feat: onIdleAction + clipboardClearSeconds settings"
```

---

### Task 2: `idle-lock.ts` — chrome.idle handling (pure)

**Files:**
- Create: `src/background/idle-lock.ts`
- Create: `src/background/idle-lock.test.ts`

**Interfaces:**
- Consumes: `OnIdleAction` (Task 1).
- Produces: `const IDLE_LOCK_ALARM = 'idle-lock'`; `type IdleState = 'active'|'idle'|'locked'`; `interface IdleLockDeps`; `createIdleLock(deps): { applyDetection(): Promise<void>; onStateChanged(state): Promise<void>; onBackstopAlarm(): Promise<void> }`.

- [ ] **Step 1: Write the failing tests**

Create `src/background/idle-lock.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { createIdleLock, type IdleLockDeps } from './idle-lock.js';

function makeDeps(over: Partial<IdleLockDeps> = {}): IdleLockDeps {
  return {
    getConfig: async () => ({ idleSeconds: 900, action: 'lock' }),
    isUnlocked: async () => true,
    lock: vi.fn(async () => {}),
    logout: vi.fn(async () => {}),
    queryState: async () => 'active',
    setDetectionInterval: vi.fn(),
    ...over,
  };
}

describe('createIdleLock', () => {
  it('locks on idle and on locked when unlocked', async () => {
    const deps = makeDeps();
    const il = createIdleLock(deps);
    await il.onStateChanged('idle');
    await il.onStateChanged('locked');
    expect(deps.lock).toHaveBeenCalledTimes(2);
    expect(deps.logout).not.toHaveBeenCalled();
  });

  it('logs out when action is logout', async () => {
    const deps = makeDeps({ getConfig: async () => ({ idleSeconds: 60, action: 'logout' }) });
    await createIdleLock(deps).onStateChanged('idle');
    expect(deps.logout).toHaveBeenCalledTimes(1);
    expect(deps.lock).not.toHaveBeenCalled();
  });

  it('does nothing on active', async () => {
    const deps = makeDeps();
    await createIdleLock(deps).onStateChanged('active');
    expect(deps.lock).not.toHaveBeenCalled();
  });

  it('is a no-op when already locked (guards double-trigger, esp. logout)', async () => {
    const deps = makeDeps({ isUnlocked: async () => false, getConfig: async () => ({ idleSeconds: 60, action: 'logout' }) });
    const il = createIdleLock(deps);
    await il.onStateChanged('idle');
    await il.onBackstopAlarm();
    expect(deps.logout).not.toHaveBeenCalled();
    expect(deps.lock).not.toHaveBeenCalled();
  });

  it('ignores idle and locked when disabled (idleSeconds null)', async () => {
    const deps = makeDeps({ getConfig: async () => ({ idleSeconds: null, action: 'lock' }) });
    const il = createIdleLock(deps);
    await il.onStateChanged('idle');
    await il.onStateChanged('locked');
    await il.onBackstopAlarm();
    expect(deps.lock).not.toHaveBeenCalled();
    expect(deps.queryState).not.toHaveBeenCalled?.();
  });

  it('applyDetection uses idleSeconds (min 15) when enabled and a large sentinel when disabled', async () => {
    const enabled = makeDeps({ getConfig: async () => ({ idleSeconds: 5, action: 'lock' }) });
    await createIdleLock(enabled).applyDetection();
    expect(enabled.setDetectionInterval).toHaveBeenCalledWith(15); // clamped to API minimum
    const on = makeDeps({ getConfig: async () => ({ idleSeconds: 900, action: 'lock' }) });
    await createIdleLock(on).applyDetection();
    expect(on.setDetectionInterval).toHaveBeenCalledWith(900);
    const off = makeDeps({ getConfig: async () => ({ idleSeconds: null, action: 'lock' }) });
    await createIdleLock(off).applyDetection();
    expect(off.setDetectionInterval).toHaveBeenCalledWith(4 * 3600);
  });

  it('backstop alarm queries idle state and acts on idle/locked only', async () => {
    const idle = makeDeps({ queryState: vi.fn(async () => 'idle') });
    await createIdleLock(idle).onBackstopAlarm();
    expect(idle.lock).toHaveBeenCalledTimes(1);
    const active = makeDeps({ queryState: vi.fn(async () => 'active') });
    await createIdleLock(active).onBackstopAlarm();
    expect(active.lock).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/background/idle-lock.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `src/background/idle-lock.ts`**

```ts
import type { OnIdleAction } from './settings.js';

export const IDLE_LOCK_ALARM = 'idle-lock';
export type IdleState = 'active' | 'idle' | 'locked';

export interface IdleLockDeps {
  /** idleSeconds=null means idle-locking is disabled (Never/On close). */
  getConfig(): Promise<{ idleSeconds: number | null; action: OnIdleAction }>;
  isUnlocked(): Promise<boolean>;
  lock(): Promise<void>;
  logout(): Promise<void>;
  queryState(detectionSeconds: number): Promise<IdleState>;
  setDetectionInterval(seconds: number): void;
}

/** chrome.idle detection interval minimum. */
const MIN_DETECTION_SECONDS = 15;
/** When disabled, set a large interval so 'idle' rarely fires; 'locked' is ignored by the applyAction gate. */
const SENTINEL_SECONDS = 4 * 3600;

export function createIdleLock(deps: IdleLockDeps) {
  async function applyAction(idleSeconds: number | null, action: OnIdleAction): Promise<void> {
    if (idleSeconds === null) return;                 // disabled — ignores idle AND locked
    if (!(await deps.isUnlocked())) return;           // idempotent: no cascade on double-trigger
    await (action === 'logout' ? deps.logout() : deps.lock());
  }
  return {
    async applyDetection(): Promise<void> {
      const { idleSeconds } = await deps.getConfig();
      deps.setDetectionInterval(idleSeconds === null ? SENTINEL_SECONDS : Math.max(MIN_DETECTION_SECONDS, idleSeconds));
    },
    async onStateChanged(state: IdleState): Promise<void> {
      if (state !== 'idle' && state !== 'locked') return;
      const { idleSeconds, action } = await deps.getConfig();
      await applyAction(idleSeconds, action);
    },
    async onBackstopAlarm(): Promise<void> {
      const { idleSeconds, action } = await deps.getConfig();
      if (idleSeconds === null) return;
      const state = await deps.queryState(idleSeconds);
      if (state === 'idle' || state === 'locked') await applyAction(idleSeconds, action);
    },
  };
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx vitest run src/background/idle-lock.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/background/idle-lock.ts src/background/idle-lock.test.ts
git commit -m "feat: idle-lock module (chrome.idle handling, idempotent action)"
```

---

### Task 3: `clipboard.ts` — background clear scheduler (pure)

**Files:**
- Create: `src/background/clipboard.ts`
- Create: `src/background/clipboard.test.ts`

**Interfaces:**
- Produces: `const CLIPBOARD_CLEAR_ALARM = 'clipboard-clear'`; `interface ClipboardDeps`; `createClipboard(deps): { scheduleClear(): Promise<void>; handleClipboardAlarm(): Promise<void> }`.

- [ ] **Step 1: Write the failing tests**

Create `src/background/clipboard.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { createClipboard, CLIPBOARD_CLEAR_ALARM, type ClipboardDeps } from './clipboard.js';

function makeDeps(over: Partial<ClipboardDeps> = {}): ClipboardDeps {
  return {
    getClearSeconds: async () => 60,
    createAlarm: vi.fn(),
    clearAlarm: vi.fn(),
    ensureOffscreen: vi.fn(async () => {}),
    sendOffscreen: vi.fn(async () => ({ ok: true })),
    closeOffscreen: vi.fn(async () => {}),
    ...over,
  };
}

describe('createClipboard', () => {
  it('clears any pending alarm when set to never', async () => {
    const deps = makeDeps({ getClearSeconds: async () => null });
    await createClipboard(deps).scheduleClear();
    expect(deps.clearAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM);
    expect(deps.createAlarm).not.toHaveBeenCalled();
  });

  it('schedules an alarm at max(30, seconds)/60 minutes', async () => {
    const d60 = makeDeps({ getClearSeconds: async () => 60 });
    await createClipboard(d60).scheduleClear();
    expect(d60.createAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM, 1);
    const d30 = makeDeps({ getClearSeconds: async () => 30 });
    await createClipboard(d30).scheduleClear();
    expect(d30.createAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM, 0.5);
  });

  it('ensures offscreen, sends clear, then closes (close runs even if send throws)', async () => {
    const order: string[] = [];
    const deps = makeDeps({
      ensureOffscreen: vi.fn(async () => { order.push('ensure'); }),
      sendOffscreen: vi.fn(async () => { order.push('send'); return { ok: true }; }),
      closeOffscreen: vi.fn(async () => { order.push('close'); }),
    });
    await createClipboard(deps).handleClipboardAlarm();
    expect(order).toEqual(['ensure', 'send', 'close']);

    const throwing = makeDeps({ sendOffscreen: vi.fn(async () => { throw new Error('boom'); }) });
    await createClipboard(throwing).handleClipboardAlarm(); // must not reject
    expect(throwing.closeOffscreen).toHaveBeenCalledTimes(1);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/background/clipboard.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `src/background/clipboard.ts`**

```ts
export const CLIPBOARD_CLEAR_ALARM = 'clipboard-clear';

export interface ClipboardDeps {
  getClearSeconds(): Promise<number | null>;
  createAlarm(name: string, delayInMinutes: number): void;
  clearAlarm(name: string): void;
  ensureOffscreen(): Promise<void>;
  sendOffscreen(msg: { type: 'offscreen.clearClipboard' }): Promise<unknown>;
  closeOffscreen(): Promise<void>;
}

export function createClipboard(deps: ClipboardDeps) {
  return {
    /** Schedule (or cancel) the background clipboard clear. A same-named alarm replaces the prior one,
     *  so back-to-back copies collapse to a single clear at the latest deadline. */
    async scheduleClear(): Promise<void> {
      const seconds = await deps.getClearSeconds();
      if (seconds === null) { deps.clearAlarm(CLIPBOARD_CLEAR_ALARM); return; }
      deps.createAlarm(CLIPBOARD_CLEAR_ALARM, Math.max(30, seconds) / 60);
    },
    /** Fired by the alarm: clear the clipboard via the offscreen document, then close it. Failures are swallowed. */
    async handleClipboardAlarm(): Promise<void> {
      try {
        await deps.ensureOffscreen();
        await deps.sendOffscreen({ type: 'offscreen.clearClipboard' });
      } catch {
        /* swallow — re-arming risks a wake loop; the secret exposure is best-effort */
      } finally {
        await deps.closeOffscreen().catch(() => {/* ignore */});
      }
    },
  };
}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `npx vitest run src/background/clipboard.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/background/clipboard.ts src/background/clipboard.test.ts
git commit -m "feat: clipboard background-clear scheduler"
```

---

### Task 4: Offscreen document — the clipboard clearer

**Files:**
- Create: `src/offscreen.ts`
- Create: `src/offscreen.html`
- Create: `src/offscreen.test.ts`

**Interfaces:**
- Produces (exported for tests): `clearClipboard(): Promise<{ ok: true } | { ok: false; error: string }>`; `handleOffscreenMessage(message): Promise<...> | undefined`.

- [ ] **Step 1: Write the failing tests**

Create `src/offscreen.test.ts`:

```ts
// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { runtime: { onMessage: { addListener: vi.fn() } } } }));
import { clearClipboard, handleOffscreenMessage } from './offscreen.js';

beforeEach(() => { vi.restoreAllMocks(); });

describe('offscreen clipboard clearer', () => {
  it('clears via navigator.clipboard.writeText("") when available', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    const res = await clearClipboard();
    expect(writeText).toHaveBeenCalledWith('');
    expect(res).toEqual({ ok: true });
  });

  it('falls back to a textarea+execCommand overwrite when writeText throws', async () => {
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn(async () => { throw new Error('not focused'); }) } });
    const execCommand = vi.fn(() => true);
    // happy-dom lacks execCommand; stub it on document
    (document as unknown as { execCommand: unknown }).execCommand = execCommand;
    const res = await clearClipboard();
    expect(execCommand).toHaveBeenCalledWith('copy');
    expect(res).toEqual({ ok: true });
  });

  it('ignores non-clear messages', () => {
    expect(handleOffscreenMessage({ type: 'something.else' })).toBeUndefined();
    expect(handleOffscreenMessage({ type: 'offscreen.clearClipboard' })).toBeInstanceOf(Promise);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/offscreen.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `src/offscreen.ts`**

```ts
import browser from 'webextension-polyfill';

/** Clear the system clipboard. Primary: writeText(''). Fallback: overwrite with a single space via
 *  execCommand (a non-empty selection — execCommand('copy') on an EMPTY selection is a no-op). */
export async function clearClipboard(): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await navigator.clipboard.writeText('');
    return { ok: true };
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = ' ';
      document.body.append(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }
}

/** Return a Promise (response) only for our own message; otherwise undefined so we don't answer others'. */
export function handleOffscreenMessage(message: unknown): Promise<{ ok: true } | { ok: false; error: string }> | undefined {
  if (typeof message === 'object' && message !== null && (message as { type?: unknown }).type === 'offscreen.clearClipboard') {
    return clearClipboard();
  }
  return undefined;
}

browser.runtime.onMessage.addListener(handleOffscreenMessage);
```

- [ ] **Step 4: Create `src/offscreen.html`**

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Vaultwarden</title></head>
<body><script src="offscreen.js" type="module"></script></body></html>
```

- [ ] **Step 5: Run tests + typecheck**

Run: `npx vitest run src/offscreen.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/offscreen.ts src/offscreen.html src/offscreen.test.ts
git commit -m "feat: offscreen clipboard clearer"
```

---

### Task 5: Manifest permissions + build offscreen entry

**Files:**
- Modify: `src/manifest.json`
- Modify: `build.mjs`
- Test: `src/manifest.test.ts`

**Interfaces:**
- Consumes: `src/offscreen.ts` / `src/offscreen.html` (Task 4).
- Produces: `dist/offscreen.js` + `dist/offscreen.html`; manifest `permissions` include `idle`, `offscreen`.

- [ ] **Step 1: Write the failing test**

Add to `src/manifest.test.ts` inside the `describe('manifest', …)` block:

```ts
it('requests the idle and offscreen permissions', () => {
  expect(manifest.permissions).toContain('idle');
  expect(manifest.permissions).toContain('offscreen');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/manifest.test.ts`
Expected: FAIL — permissions missing.

- [ ] **Step 3: Add the permissions**

In `src/manifest.json`, change the `permissions` line to:

```json
  "permissions": ["storage", "alarms", "clipboardRead", "clipboardWrite", "contextMenus", "idle", "offscreen"],
```

- [ ] **Step 4: Add the offscreen build entry**

In `build.mjs`, add to `entryPoints` (after the `content/*` entries):

```js
    offscreen: 'src/offscreen.ts',
```

In `copyStatic()`, add after the icons copy (a top-level file, not under `ui/`):

```js
  await cp('src/offscreen.html', join(outdir, 'offscreen.html'));
```

- [ ] **Step 5: Run test + build to verify**

Run: `npx vitest run src/manifest.test.ts && npm run build`
Expected: test PASS; build prints "build done". Confirm the artifacts exist:

Run: `ls dist/offscreen.js dist/offscreen.html`
Expected: both listed.

- [ ] **Step 6: Commit**

```bash
git add src/manifest.json build.mjs src/manifest.test.ts
git commit -m "feat: idle + offscreen permissions and offscreen build entry"
```

---

### Task 6: Protocol + router — settings.saveSecurity, clipboard.scheduleClear, settings.get fields

**Files:**
- Modify: `src/messaging/protocol.ts`
- Modify: `src/background/router.ts`
- Test: `src/background/router.test.ts`

**Interfaces:**
- Consumes: `OnIdleAction`, `ClipboardClearSetting` (Task 1).
- Produces: requests `{ type:'settings.saveSecurity'; onIdleAction; clipboardClearSeconds }` and `{ type:'clipboard.scheduleClear' }`; `settings.get` response gains `onIdleAction`, `clipboardClearSeconds`.

- [ ] **Step 1: Write the failing test**

Add to `src/background/router.test.ts`:

```ts
it('saves security settings and schedules a clipboard clear', async () => {
  const settings = {
    getServerUrl: async () => 'https://x', getDefaultUriMatchStrategy: async () => 0,
    getLockTimeout: async () => '15', getOnIdleAction: vi.fn(async () => 'lock'),
    getClipboardClearSetting: vi.fn(async () => '60'), saveOnIdleAction: vi.fn(async () => {}),
    saveClipboardClearSetting: vi.fn(async () => {}), saveServerUrl: vi.fn(), saveDefaultUriMatchStrategy: vi.fn(), saveLockTimeout: vi.fn(),
  };
  const clipboard = { scheduleClear: vi.fn(async () => {}) };
  const router = createRouter({ auth: {} as never, vault: {} as never, settings: settings as never, clipboard } as never);

  const got = await router.handle({ type: 'settings.get' } as never);
  expect(got).toMatchObject({ ok: true, data: { onIdleAction: 'lock', clipboardClearSeconds: '60' } });

  await router.handle({ type: 'settings.saveSecurity', onIdleAction: 'logout', clipboardClearSeconds: '120' } as never);
  expect(settings.saveOnIdleAction).toHaveBeenCalledWith('logout');
  expect(settings.saveClipboardClearSetting).toHaveBeenCalledWith('120');

  await router.handle({ type: 'clipboard.scheduleClear' } as never);
  expect(clipboard.scheduleClear).toHaveBeenCalledTimes(1);
});
```

(Match the file's existing `createRouter({...})` construction; add `getOnIdleAction`/`getClipboardClearSetting`/`saveOnIdleAction`/`saveClipboardClearSetting` to any shared fake-settings helper it uses.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/background/router.test.ts -t "security settings"`
Expected: FAIL — types/cases missing.

- [ ] **Step 3: Extend the protocol**

In `src/messaging/protocol.ts`, add the import `OnIdleAction, ClipboardClearSetting` to the `./settings.js` type import, add the two requests after `settings.save`:

```ts
  | { type: 'settings.saveSecurity'; onIdleAction: OnIdleAction; clipboardClearSeconds: ClipboardClearSetting }
  | { type: 'clipboard.scheduleClear' }
```

Change the `settings.get` response variant to:

```ts
  | { ok: true; data: { serverUrl?: string; defaultUriMatchStrategy: UriMatchStrategySetting; lockTimeout: LockTimeoutSetting; onIdleAction: OnIdleAction; clipboardClearSeconds: ClipboardClearSetting } }
```

- [ ] **Step 4: Extend the router**

In `src/background/router.ts`, add to `RouterDeps.settings` (import the two types):

```ts
    getOnIdleAction(): Promise<OnIdleAction>;
    saveOnIdleAction(value: OnIdleAction): Promise<void>;
    getClipboardClearSetting(): Promise<ClipboardClearSetting>;
    saveClipboardClearSetting(value: ClipboardClearSetting): Promise<void>;
```

Add an optional clipboard dep to `RouterDeps`:

```ts
  clipboard?: { scheduleClear(): Promise<void> };
```

Update the `settings.get` case to include the two fields:

```ts
          case 'settings.get': {
            const serverUrl = await deps.settings.getServerUrl();
            const defaultUriMatchStrategy = await deps.settings.getDefaultUriMatchStrategy();
            const lockTimeout = await deps.settings.getLockTimeout();
            const onIdleAction = await deps.settings.getOnIdleAction();
            const clipboardClearSeconds = await deps.settings.getClipboardClearSetting();
            const base = { defaultUriMatchStrategy, lockTimeout, onIdleAction, clipboardClearSeconds };
            return { ok: true, data: serverUrl === undefined ? base : { serverUrl, ...base } };
          }
```

Add two cases after `settings.save`:

```ts
          case 'settings.saveSecurity':
            await deps.settings.saveOnIdleAction(request.onIdleAction);
            await deps.settings.saveClipboardClearSetting(request.clipboardClearSeconds);
            return { ok: true, data: null };
          case 'clipboard.scheduleClear':
            if (!deps.clipboard) throw new Error('clipboard is not wired');
            await deps.clipboard.scheduleClear();
            return { ok: true, data: null };
```

- [ ] **Step 5: Run tests + typecheck**

Run: `npx vitest run src/background/router.test.ts && npm run typecheck`
Expected: PASS. (If typecheck flags `background/index.ts` for the new `RouterDeps.settings` methods, that is fixed in Task 7 where the real settings service — which has them from Task 1 — is passed.)

- [ ] **Step 6: Commit**

```bash
git add src/messaging/protocol.ts src/background/router.ts src/background/router.test.ts
git commit -m "feat: settings.saveSecurity + clipboard.scheduleClear routes; settings.get security fields"
```

---

### Task 7: Wire idle-lock + clipboard in `background/index.ts`; retire polling

**Files:**
- Modify: `src/background/index.ts`
- Delete: `src/background/alarms.ts`, `src/background/alarms.test.ts`

**Interfaces:**
- Consumes: `createIdleLock`/`IDLE_LOCK_ALARM` (Task 2), `createClipboard`/`CLIPBOARD_CLEAR_ALARM` (Task 3), settings (Task 1), router+clipboard dep (Task 6).

- [ ] **Step 1: Replace the alarm/idle wiring**

In `src/background/index.ts`:

(a) Replace the `createAlarmHandlers`/`IDLE_LOCK_ALARM` import with:

```ts
import { createIdleLock, IDLE_LOCK_ALARM } from './idle-lock.js';
import { createClipboard, CLIPBOARD_CLEAR_ALARM } from './clipboard.js';
```

(b) Replace the `const alarms = createAlarmHandlers({...})` block with the idle-lock + clipboard construction:

```ts
const idleLock = createIdleLock({
  getConfig: async () => ({ idleSeconds: (await settings.getIdleMs()) === null ? null : (await settings.getIdleMs())! / 1000, action: await settings.getOnIdleAction() }),
  isUnlocked: async () => (await auth.getState()) === 'unlocked',
  lock: () => auth.lock(),
  logout: () => auth.logout(),
  queryState: (seconds) => browser.idle.queryState(seconds) as Promise<'active' | 'idle' | 'locked'>,
  setDetectionInterval: (seconds) => browser.idle.setDetectionInterval(seconds),
});

const offscreenApi = (globalThis as unknown as { chrome?: {
  offscreen?: { createDocument(o: { url: string; reasons: string[]; justification: string }): Promise<void>; closeDocument(): Promise<void> };
  runtime?: { getContexts?(o: { contextTypes: string[] }): Promise<unknown[]> };
} }).chrome;

const clipboard = createClipboard({
  getClearSeconds: () => settings.getClipboardClearSeconds(),
  createAlarm: (name, delayInMinutes) => browser.alarms.create(name, { delayInMinutes }),
  clearAlarm: (name) => { void browser.alarms.clear(name); },
  ensureOffscreen: async () => {
    const ctx = (await offscreenApi?.runtime?.getContexts?.({ contextTypes: ['OFFSCREEN_DOCUMENT'] })) ?? [];
    if (ctx.length === 0) {
      try { await offscreenApi?.offscreen?.createDocument({ url: 'offscreen.html', reasons: ['CLIPBOARD'], justification: 'Clear the clipboard after the copy auto-clear delay' }); }
      catch { /* already exists */ }
    }
  },
  sendOffscreen: (msg) => browser.runtime.sendMessage(msg),
  closeOffscreen: async () => { try { await offscreenApi?.offscreen?.closeDocument(); } catch { /* none open */ } },
});
```

(c) Register the idle listener + initial detection (near the `contextMenu.refresh()` call):

```ts
browser.idle.onStateChanged.addListener((state) => { void idleLock.onStateChanged(state as 'active' | 'idle' | 'locked'); });
void idleLock.applyDetection();
```

(d) In `onInstalled`, keep `browser.alarms.create(IDLE_LOCK_ALARM, { periodInMinutes: 1 })` and add `void idleLock.applyDetection();`.

(e) Replace the `onMessage` listener body:

```ts
browser.runtime.onMessage.addListener((message: unknown) => {
  // Do not hijack the offscreen document's own responses.
  if (typeof message === 'object' && message !== null && typeof (message as { type?: unknown }).type === 'string'
      && (message as { type: string }).type.startsWith('offscreen.')) {
    return; // synchronous return, no Promise
  }
  return (async () => {
    const response = await router.handle(message as RequestMessage);
    const type = (message as { type?: unknown }).type;
    if (typeof type === 'string') {
      if (shouldRefreshMenu(type)) void contextMenu.refresh().catch(() => {});
      if (type === 'settings.save' || type === 'settings.saveSecurity') void idleLock.applyDetection();
    }
    return response;
  })();
});
```

(f) Replace the `onAlarm` listener to dispatch both alarms:

```ts
browser.alarms.onAlarm.addListener((alarm) => {
  void (async () => {
    if (alarm.name === IDLE_LOCK_ALARM) await idleLock.onBackstopAlarm();
    else if (alarm.name === CLIPBOARD_CLEAR_ALARM) await clipboard.handleClipboardAlarm();
  })();
});
```

(g) Pass `clipboard` into the router deps: in the `createRouter({...})` call add `clipboard: { scheduleClear: () => clipboard.scheduleClear() }`.

- [ ] **Step 2: Delete the retired module**

```bash
git rm src/background/alarms.ts src/background/alarms.test.ts
```

- [ ] **Step 3: Typecheck + build**

Run: `npm run typecheck && npm run build && npm test`
Expected: typecheck clean; build done (with `dist/offscreen.js`); full suite green (the deleted alarms tests are gone; idle-lock/clipboard tests cover the logic).

- [ ] **Step 4: Commit**

```bash
git add src/background/index.ts
git commit -m "feat: wire chrome.idle auto-lock + offscreen clipboard clear; retire lastActivity polling"
```

---

### Task 8: Options UI — Security section (decoupled)

**Files:**
- Modify: `src/ui/options/options.ts`
- Modify: `src/ui/options/options.html`

**Interfaces:**
- Consumes: `settings.get` fields + `settings.saveSecurity` (Task 6).

- [ ] **Step 1: Add the markup**

In `src/ui/options/options.html`, add a Security section (outside the serverUrl `<form id="settingsForm">`, so it doesn't submit through it) with two selects and a warning slot:

```html
<section class="card">
  <h2>Security</h2>
  <label for="onIdleAction">On idle timeout / system lock</label>
  <select id="onIdleAction"><option value="lock">Lock</option><option value="logout">Log out</option></select>
  <p id="idleActionWarning" class="help"></p>
  <label for="clipboardClear">Clear copied values after</label>
  <select id="clipboardClear">
    <option value="never">Never</option><option value="30">30 seconds</option><option value="60">1 minute</option><option value="120">2 minutes</option><option value="300">5 minutes</option>
  </select>
  <div id="securityStatus"></div>
</section>
```

- [ ] **Step 2: Wire save-on-change**

In `src/ui/options/options.ts`, add element refs + load in `init()` + change handlers:

```ts
const onIdleActionInput = document.getElementById('onIdleAction') as HTMLSelectElement;
const clipboardClearInput = document.getElementById('clipboardClear') as HTMLSelectElement;
const idleActionWarning = document.getElementById('idleActionWarning')!;

function updateIdleWarning() {
  idleActionWarning.textContent = onIdleActionInput.value === 'logout'
    ? 'Log out will end your session (and disable PIN unlock) on every idle timeout and system lock.'
    : '';
}

async function saveSecurity() {
  const response = await sendRequest({ type: 'settings.saveSecurity', onIdleAction: onIdleActionInput.value as 'lock' | 'logout', clipboardClearSeconds: clipboardClearInput.value as never });
  const el = document.getElementById('securityStatus')!;
  el.innerHTML = response.ok ? '' : `<div class="toast error">${escapeHtml(response.error.message)}</div>`;
}

onIdleActionInput.addEventListener('change', () => { updateIdleWarning(); void saveSecurity(); });
clipboardClearInput.addEventListener('change', () => void saveSecurity());
```

In `init()`, after reading the existing settings, also set the new selects from the `settings.get` response (`onIdleAction`, `clipboardClearSeconds`) and call `updateIdleWarning()`. Cast the `response.data` type to include the two new fields.

- [ ] **Step 3: Typecheck + build**

Run: `npm run typecheck && npm run build`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add src/ui/options/options.ts src/ui/options/options.html
git commit -m "feat: options Security section (idle action + clipboard clear, save-on-change)"
```

---

### Task 9: Popup — route clipboard clear to background

**Files:**
- Modify: `src/ui/popup/popup.ts`

**Interfaces:**
- Consumes: `clipboard.scheduleClear` + `settings.get.clipboardClearSeconds` (Task 6).

- [ ] **Step 1: Replace `copyWithClear`**

In `src/ui/popup/popup.ts`, replace the `copyWithClear` body (~line 2600) with:

```ts
async function copyWithClear(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
  void sendRequest({ type: 'clipboard.scheduleClear' }); // background clears via offscreen; survives popup close
}
```

- [ ] **Step 2: Show the configured duration in the status**

Add a module-level `let clipboardClearSeconds: number | null = 60;`. Where the popup already calls `settings.get` on open (search `type: 'settings.get'`), read `clipboardClearSeconds` from the response (`'never' → null`, else `Number(...)`) into that variable. Update the `copyValue` status string (~line 2149) to:

```ts
    setDetailStatus(`${label} copied.${clipboardClearSeconds === null ? '' : ` Clipboard clears in ${clipboardClearSeconds} s.`}`, false);
```

(If the popup does not already fetch `settings.get`, fetch it once during the unlocked-view init and store `clipboardClearSeconds`; cast the response data to include `clipboardClearSeconds`.)

- [ ] **Step 3: Typecheck + build**

Run: `npm run typecheck && npm run build && npm test`
Expected: clean; full suite green.

- [ ] **Step 4: Commit**

```bash
git add src/ui/popup/popup.ts
git commit -m "feat: popup routes clipboard auto-clear to the background offscreen path"
```

---

## Manual smoke test (after Task 9) — REQUIRED to pin the clipboard mechanism

Load the unpacked `dist/` in Chrome, sign in, then:
1. **Idle lock:** set On-idle to Lock and timeout to 1 minute (via a temporary short value if needed for testing); leave the machine idle → the vault locks. Set On-idle to Log out → after idle it logs out (confirm the warning showed).
2. **System lock:** lock the OS screen (Win+L) while unlocked → the vault applies the configured action on return.
3. **Clipboard clear (pins the mechanism):** copy a password, CLOSE the popup, wait the configured duration (default 60s), then paste elsewhere → the clipboard is empty (or a single space). **If it is NOT cleared, the `writeText('')` path failed silently and the execCommand fallback is what runs — verify the fallback path works; if neither clears, escalate.** Try `never` → clipboard is not cleared.
4. **Security settings decoupling:** change On-idle action with an empty/unchanged serverUrl → it saves with NO host-permission prompt.

Record the observed working clipboard path (writeText vs execCommand) in the PR notes.

---

## Self-Review Notes

- **Spec coverage:** §5 settings (T1), §6 idle-lock incl. isUnlocked guard + sentinel + min-15 (T2), §7 clipboard scheduler (T3) + offscreen clearer (T4) + popup route (T9) + SW guard/onAlarm/wiring (T7), §8 options decoupled UI (T8), §9 protocol/router (T6), §10 manifest/build (T5), §11 security (guard in T2, no-plaintext in T3/T4), §12 tests (each task) + manual smoke. All mapped.
- **Type consistency:** `OnIdleAction`/`ClipboardClearSetting` (T1) → T2/T6/T8/T9; `IdleLockDeps`/`createIdleLock` (T2) → T7; `ClipboardDeps`/`createClipboard` (T3) → T7; `IDLE_LOCK_ALARM`/`CLIPBOARD_CLEAR_ALARM` consistent across T2/T3/T7; request type names match router cases (T6) and popup/options senders (T8/T9).
- **No placeholders:** pure/backend tasks (T1–T6) carry complete code; wiring/UI tasks (T7–T9) give concrete edits at named anchors, gated by typecheck+build; the clipboard mechanism is pinned by the required manual smoke.
