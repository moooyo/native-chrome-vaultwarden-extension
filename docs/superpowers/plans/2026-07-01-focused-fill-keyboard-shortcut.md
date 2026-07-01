# Focused-fill Keyboard Shortcut Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one Chrome keyboard shortcut that fills the focused field's form (login / card / identity) — single match fills directly, multiple opens the existing popover picker.

**Architecture:** `chrome.commands.onCommand` fires in the background (no DOM access) → a thin, testable `handleFocusedFillCommand` relays `{type:'autofill.focusedFill'}` to the active tab's frames → the focused leaf frame resolves `document.activeElement` to its owning form via a pure `resolveFocusedFill`, then a pure `runFocusedFill` orchestrator (injected deps) reuses the existing worker requests and fill functions. No new worker/router request types.

**Tech Stack:** TypeScript, MV3 (`webextension-polyfill`), vitest + happy-dom, existing content-script autofill modules.

## Global Constraints

- **No new worker/router request types** — reuse `autofill.findCandidates` / `autofill.getCredentials` / `autofill.findFillItems` / `autofill.getFillData`.
- **Security invariants (must hold):** the command message `{type:'autofill.focusedFill'}` carries NO vault data; card/identity release stays gated by the worker's reprompt + national-ID stripping; login release stays gated by worker URL-matching + reprompt; the shortcut relaxes none of these. Trust derives from the browser-dispatched command + the extension message channel (a web page cannot forge `runtime.onMessage`), exactly like the shipped context-menu fill.
- **Frame routing:** `document.hasFocus()` is true for the focused document AND all ancestors; only the leaf frame whose `activeElement` is a real field acts. Ancestor frames (`activeElement` is an `<iframe>`/`<frame>` element) and non-focused frames return silently — no notice.
- **Notices are English literals** (matches existing `showNotice`). No i18n.
- **Default keybinding:** `Ctrl+Shift+F` (mac `Command+Shift+F`), user-remappable at `chrome://extensions/shortcuts`.
- **Out of scope:** Shadow-DOM / contenteditable fields (same limitation as existing autofill), custom-keybinding UI, multi-command, page-level "guess the form" fallback, per-candidate 🔒 badge in the picker.
- Spec: `docs/superpowers/specs/2026-07-01-focused-fill-keyboard-shortcut-design.md`.

---

### Task 1: Manifest command declaration

**Files:**
- Modify: `src/manifest.json` (add top-level `commands`)
- Test: `src/manifest.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: manifest `commands['autofill-focused']` with `suggested_key.default` and `description`.

- [ ] **Step 1: Write the failing test**

Add inside the `describe('manifest', …)` block in `src/manifest.test.ts`:

```ts
it('declares the focused-fill keyboard command', () => {
  const cmd = (manifest as { commands?: Record<string, { description?: string; suggested_key?: { default?: string } }> }).commands?.['autofill-focused'];
  expect(cmd).toBeDefined();
  expect(cmd?.description).toBeTruthy();
  expect(cmd?.suggested_key?.default).toBe('Ctrl+Shift+F');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/manifest.test.ts`
Expected: FAIL — `cmd` is `undefined`.

- [ ] **Step 3: Add the commands block**

In `src/manifest.json`, add a top-level `"commands"` key (after the `content_scripts` array, still inside the root object):

```json
  "commands": {
    "autofill-focused": {
      "suggested_key": { "default": "Ctrl+Shift+F", "mac": "Command+Shift+F" },
      "description": "Fill the focused login, card, or identity field from Vaultwarden"
    }
  }
```

(Remember the comma after the preceding `content_scripts` array.)

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/manifest.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/manifest.json src/manifest.test.ts
git commit -m "feat: declare autofill-focused keyboard command in manifest"
```

---

### Task 2: `computeFillExclusion` + `resolveFocusedFill` (pure detection)

**Files:**
- Create: `src/content/focused-fill.ts`
- Create: `src/content/focused-fill.test.ts`
- Modify: `src/content/autofill.ts` (refactor `attachPopovers` to consume `computeFillExclusion`)

**Interfaces:**
- Consumes: `detectLoginForms(root?)`, `detectCardForms(root?, exclude?)`, `detectIdentityForms(root?, exclude?)` (all already take `root: ParentNode = document`); `DetectedLoginForm` (`{ id, usernameInput?, passwordInput?, totpInput?, anchor }`), `DetectedFillForm` (`{ kind, id, fields: Map<Role, FillFieldElement>, anchor }`).
- Produces:
  - `computeFillExclusion(root?: ParentNode): { loginForms: DetectedLoginForm[]; exclude: Set<Element> }`
  - `resolveFocusedFill(activeEl: Element | null, root?: ParentNode): FocusedTarget`
  - `type FocusedTarget = { kind: 'login'; form: DetectedLoginForm } | { kind: 'card'; form: DetectedFillForm } | { kind: 'identity'; form: DetectedFillForm } | { kind: 'none' }`

- [ ] **Step 1: Write the failing tests**

Create `src/content/focused-fill.test.ts`:

```ts
// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { computeFillExclusion, resolveFocusedFill } from './focused-fill.js';

describe('resolveFocusedFill', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('classifies a focused login password field as login', () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const pw = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    pw.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'login' });
  });

  it('classifies a focused card-number field as card', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"></form>';
    const num = document.querySelector<HTMLInputElement>('input[autocomplete="cc-number"]')!;
    num.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'card' });
  });

  it('classifies a focused address field as identity', () => {
    document.body.innerHTML = '<form><input autocomplete="given-name"><input autocomplete="family-name"><input autocomplete="street-address"><input autocomplete="postal-code"></form>';
    const addr = document.querySelector<HTMLInputElement>('input[autocomplete="street-address"]')!;
    addr.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'identity' });
  });

  it('returns none for a fillable-but-unrecognized field and for the body', () => {
    document.body.innerHTML = '<input type="search">';
    document.querySelector<HTMLInputElement>('input')!.focus();
    expect(resolveFocusedFill(document.activeElement)).toEqual({ kind: 'none' });
    document.body.innerHTML = '';
    expect(resolveFocusedFill(document.body)).toEqual({ kind: 'none' });
  });

  it('resolves a CVC-rendered-as-password field to card, not login (carve-out)', () => {
    document.body.innerHTML = '<form><input autocomplete="username" name="u"><input autocomplete="cc-number" name="c"><input type="password" autocomplete="cc-csc" name="cvc"><button type="submit">Pay</button></form>';
    const cvc = document.querySelector<HTMLInputElement>('input[name="cvc"]')!;
    cvc.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'card' });
  });
});

describe('computeFillExclusion', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('excludes real login fields but drops a CVC-as-password login form', () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const { loginForms, exclude } = computeFillExclusion();
    expect(loginForms).toHaveLength(1);
    const pw = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    expect(exclude.has(pw)).toBe(true);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/content/focused-fill.test.ts`
Expected: FAIL — module `./focused-fill.js` not found.

- [ ] **Step 3: Create `src/content/focused-fill.ts`**

```ts
import { detectLoginForms, type DetectedLoginForm } from './form-detection.js';
import { detectCardForms, detectIdentityForms, type DetectedFillForm } from './field-detection.js';

export type FocusedTarget =
  | { kind: 'login'; form: DetectedLoginForm }
  | { kind: 'card'; form: DetectedFillForm }
  | { kind: 'identity'; form: DetectedFillForm }
  | { kind: 'none' };

export interface FillExclusion {
  /** Real login forms — a login form whose password field is actually a card CVC is dropped. */
  loginForms: DetectedLoginForm[];
  /** The username/password/totp fields of those login forms, to keep them out of card/identity detection. */
  exclude: Set<Element>;
}

/**
 * Single source of truth for the login/card/identity carve-out. Mirrors what attachPopovers did inline:
 * build the set of card CVC fields first, then treat a "login" form whose password IS a CVC as not-a-login.
 */
export function computeFillExclusion(root: ParentNode = document): FillExclusion {
  const cardCodeFields = new Set<Element>();
  for (const card of detectCardForms(root)) {
    const code = card.fields.get('code');
    if (code) cardCodeFields.add(code);
  }
  const loginForms: DetectedLoginForm[] = [];
  const exclude = new Set<Element>();
  for (const form of detectLoginForms(root)) {
    if (form.passwordInput && cardCodeFields.has(form.passwordInput)) continue; // a CVC, not a login
    loginForms.push(form);
    for (const el of [form.usernameInput, form.passwordInput, form.totpInput]) if (el) exclude.add(el);
  }
  return { loginForms, exclude };
}

/**
 * Determine which detected form the focused element belongs to. Precedence (identical to attachPopovers):
 * CVC carve-out (inside computeFillExclusion) → login → card → identity → none.
 */
export function resolveFocusedFill(activeEl: Element | null, root: ParentNode = document): FocusedTarget {
  if (!(activeEl instanceof HTMLInputElement || activeEl instanceof HTMLSelectElement)) return { kind: 'none' };
  const { loginForms, exclude } = computeFillExclusion(root);
  for (const form of loginForms) {
    if (activeEl === form.usernameInput || activeEl === form.passwordInput || activeEl === form.totpInput) {
      return { kind: 'login', form };
    }
  }
  for (const form of detectCardForms(root, exclude)) {
    for (const field of form.fields.values()) if (field === activeEl) return { kind: 'card', form };
  }
  for (const form of detectIdentityForms(root, exclude)) {
    for (const field of form.fields.values()) if (field === activeEl) return { kind: 'identity', form };
  }
  return { kind: 'none' };
}
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `npx vitest run src/content/focused-fill.test.ts`
Expected: PASS (all 6).

- [ ] **Step 5: Refactor `attachPopovers` to use `computeFillExclusion`**

In `src/content/autofill.ts`, add to the imports:

```ts
import { computeFillExclusion } from './focused-fill.js';
```

Replace the body of `attachPopovers` (the block that builds `cardCodeFields` + `exclude` inline, currently `src/content/autofill.ts:93-110`) with:

```ts
function attachPopovers(getFrameUrl: FrameUrlProvider): void {
  if (!isHttpUrl(getFrameUrl())) return;
  const { loginForms, exclude } = computeFillExclusion(document);
  for (const form of loginForms) {
    attachIfNew(form.id, () => attachPopover(getFrameUrl, form));
  }
  for (const form of [...detectCardForms(document, exclude), ...detectIdentityForms(document, exclude)]) {
    attachIfNew(form.id, () => attachFillPopover(form));
  }
}
```

- [ ] **Step 6: Run the full content suite + typecheck to verify no regression**

Run: `npx vitest run src/content/ && npm run typecheck`
Expected: PASS — existing autofill tests still green (behavior-preserving refactor), typecheck clean.

- [ ] **Step 7: Commit**

```bash
git add src/content/focused-fill.ts src/content/focused-fill.test.ts src/content/autofill.ts
git commit -m "feat: computeFillExclusion + resolveFocusedFill; reuse in attachPopovers"
```

---

### Task 3: `popover.open()` programmatic entry

**Files:**
- Modify: `src/content/popover.ts`
- Test: `src/content/popover.test.ts`

**Interfaces:**
- Consumes: existing `AutofillPopoverOptions.onOpen`.
- Produces: `AutofillPopover.open(): void` — invokes `options.onOpen()` directly (no synthetic DOM event, so the shield click's `isTrusted` guard is untouched and open() still works from a trusted message handler).

- [ ] **Step 1: Write the failing test**

Add to `src/content/popover.test.ts` (match the file's existing import/setup style):

```ts
it('open() invokes onOpen without a DOM event', () => {
  const anchor = document.createElement('input');
  document.body.append(anchor);
  const onOpen = vi.fn();
  const popover = createAutofillPopover({ anchor, onOpen, onSelect: () => {} });
  popover.open();
  expect(onOpen).toHaveBeenCalledTimes(1);
});
```

Ensure `createAutofillPopover` and `vi` are imported at the top of the test file (they are, if other tests use them — otherwise add `import { createAutofillPopover } from './popover.js';` and `vi` to the vitest import).

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/content/popover.test.ts`
Expected: FAIL — `popover.open is not a function`.

- [ ] **Step 3: Add `open()` to the interface and the returned object**

In `src/content/popover.ts`, add to the `AutofillPopover` interface (after `root`):

```ts
  /** Programmatically open the panel (runs the same onOpen path as a trusted shield click). */
  open(): void;
```

In the object returned by `createAutofillPopover`, add the method (place it right after `root: shadow,`):

```ts
    open() {
      options.onOpen();
    },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/content/popover.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/content/popover.ts src/content/popover.test.ts
git commit -m "feat: add programmatic AutofillPopover.open()"
```

---

### Task 4: `runFocusedFill` orchestrator (pure, injected deps)

**Files:**
- Modify: `src/content/focused-fill.ts` (append orchestrator + deps types)
- Test: `src/content/focused-fill.test.ts` (append `runFocusedFill` suite)

**Interfaces:**
- Consumes: `FocusedTarget` (Task 2); protocol types `AutofillCandidate`, `AutofillCredentials`, `FillItemCandidate`, `CardFillData`, `IdentityFillData`, `FillKind`; `DetectedLoginForm`, `DetectedFillForm`.
- Produces:
  - `type FillOutcome<T> = { ok: true; data: T } | { ok: false; message: string }`
  - `interface FocusedFillDeps { … }` (see code)
  - `runFocusedFill(target: FocusedTarget, deps: FocusedFillDeps): Promise<void>`
  - `const NOTICE_FOCUS`, `const NOTICE_PAGE_CHANGED` (exported string constants)

- [ ] **Step 1: Write the failing tests**

Append to `src/content/focused-fill.test.ts`:

```ts
import { runFocusedFill, NOTICE_FOCUS, NOTICE_PAGE_CHANGED, type FocusedFillDeps } from './focused-fill.js';

function makeDeps(over: Partial<FocusedFillDeps> = {}): FocusedFillDeps {
  return {
    frameUrl: () => 'https://ex.com',
    loginCandidates: async () => ({ ok: true, data: [] }),
    loginCredentials: async () => ({ ok: true, data: { username: 'u', password: 'p' } }),
    fillItems: async () => ({ ok: true, data: [] }),
    fillData: async () => ({ ok: true, data: {} }),
    fillLogin: vi.fn(),
    fillCard: vi.fn(),
    fillIdentity: vi.fn(),
    openPicker: vi.fn(),
    notify: vi.fn(),
    ...over,
  };
}
const liveInput = () => { const i = document.createElement('input'); document.body.append(i); return i; };

describe('runFocusedFill', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('notifies to focus a field when target is none', async () => {
    const deps = makeDeps();
    await runFocusedFill({ kind: 'none' }, deps);
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_FOCUS);
  });

  it('fills a login directly on a single URL match', async () => {
    const pw = liveInput();
    const form = { id: 'f1', form: null, passwordInput: pw, anchor: pw };
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' } as never] }),
      loginCredentials: async () => ({ ok: true, data: { password: 'secret' } }),
    });
    await runFocusedFill({ kind: 'login', form: form as never }, deps);
    expect(deps.fillLogin).toHaveBeenCalledTimes(1);
    expect(deps.openPicker).not.toHaveBeenCalled();
  });

  it('opens the picker when a login has multiple matches', async () => {
    const deps = makeDeps({ loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }, { id: 'b' }] as never }) });
    await runFocusedFill({ kind: 'login', form: { id: 'f2' } as never }, deps);
    expect(deps.openPicker).toHaveBeenCalledWith('f2');
    expect(deps.fillLogin).not.toHaveBeenCalled();
  });

  it('notifies "No matching logins" on zero login matches', async () => {
    const deps = makeDeps({ loginCandidates: async () => ({ ok: true, data: [] }) });
    await runFocusedFill({ kind: 'login', form: { id: 'f3' } as never }, deps);
    expect(deps.notify).toHaveBeenCalledWith('No matching logins');
  });

  it('aborts a login fill if the frame URL changed during the round-trip', async () => {
    const pw = liveInput();
    let url = 'https://ex.com';
    const deps = makeDeps({
      frameUrl: () => url,
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' }] as never }),
      loginCredentials: async () => { url = 'https://evil.com'; return { ok: true, data: { password: 'secret' } }; },
      fillLogin: vi.fn(),
    });
    await runFocusedFill({ kind: 'login', form: { id: 'f4', passwordInput: pw, anchor: pw, form: null } as never }, deps);
    expect(deps.fillLogin).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('fills the single card and passes reprompt errors through as notices', async () => {
    const field = liveInput();
    const form = { kind: 'card', id: 'card1', fields: new Map([['number', field]]), anchor: field };
    const ok = makeDeps({ fillItems: async () => ({ ok: true, data: [{ id: 'x' } as never] }), fillData: async () => ({ ok: true, data: { number: '4111' } }) });
    await runFocusedFill({ kind: 'card', form: form as never }, ok);
    expect(ok.fillCard).toHaveBeenCalledTimes(1);

    const reprompt = makeDeps({ fillItems: async () => ({ ok: true, data: [{ id: 'x' } as never] }), fillData: async () => ({ ok: false, message: 'Protected item — open the extension to verify' }) });
    await runFocusedFill({ kind: 'card', form: form as never }, reprompt);
    expect(reprompt.notify).toHaveBeenCalledWith('Protected item — open the extension to verify');
    expect(reprompt.fillCard).not.toHaveBeenCalled();
  });

  it('notifies "No saved cards" / "No saved identities" on empty vault', async () => {
    const card = makeDeps({ fillItems: async () => ({ ok: true, data: [] }) });
    await runFocusedFill({ kind: 'card', form: { id: 'c', kind: 'card', fields: new Map(), anchor: document.createElement('div') } as never }, card);
    expect(card.notify).toHaveBeenCalledWith('No saved cards');
    const id = makeDeps({ fillItems: async () => ({ ok: true, data: [] }) });
    await runFocusedFill({ kind: 'identity', form: { id: 'i', kind: 'identity', fields: new Map(), anchor: document.createElement('div') } as never }, id);
    expect(id.notify).toHaveBeenCalledWith('No saved identities');
  });

  it('aborts a card fill if the form fields detached during the round-trip', async () => {
    const field = document.createElement('input'); // never appended → isConnected false
    const form = { kind: 'card', id: 'c9', fields: new Map([['number', field]]), anchor: field };
    const deps = makeDeps({ fillItems: async () => ({ ok: true, data: [{ id: 'x' }] as never }), fillData: async () => ({ ok: true, data: { number: '4111' } }) });
    await runFocusedFill({ kind: 'card', form: form as never }, deps);
    expect(deps.fillCard).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/content/focused-fill.test.ts`
Expected: FAIL — `runFocusedFill` not exported.

- [ ] **Step 3: Append the orchestrator to `src/content/focused-fill.ts`**

Add imports at the top of the file:

```ts
import type { AutofillCandidate, AutofillCredentials, FillItemCandidate, CardFillData, IdentityFillData, FillKind } from '../messaging/protocol.js';
```

Append at the end of the file:

```ts
export const NOTICE_FOCUS = 'Focus a login, card, or identity field, then use the shortcut';
export const NOTICE_PAGE_CHANGED = 'Page changed before autofill';

export type FillOutcome<T> = { ok: true; data: T } | { ok: false; message: string };

export interface FocusedFillDeps {
  frameUrl(): string;
  loginCandidates(frameUrl: string): Promise<FillOutcome<AutofillCandidate[]>>;
  loginCredentials(cipherId: string, frameUrl: string): Promise<FillOutcome<AutofillCredentials>>;
  fillItems(kind: FillKind): Promise<FillOutcome<FillItemCandidate[]>>;
  fillData(cipherId: string, kind: FillKind): Promise<FillOutcome<CardFillData | IdentityFillData>>;
  fillLogin(form: DetectedLoginForm, creds: AutofillCredentials): void;
  fillCard(form: DetectedFillForm, data: CardFillData): void;
  fillIdentity(form: DetectedFillForm, data: IdentityFillData): void;
  openPicker(formId: string): void;
  notify(message: string): void;
}

function loginFormLive(form: DetectedLoginForm): boolean {
  const fields = [form.usernameInput, form.passwordInput, form.totpInput].filter((f): f is HTMLInputElement => Boolean(f));
  return fields.length > 0 && fields.every((f) => f.isConnected);
}

function fillFormLive(form: DetectedFillForm): boolean {
  const fields = [...form.fields.values()];
  return fields.length > 0 && fields.every((f) => f.isConnected);
}

/** Resolve a focused target to an autofill action, reusing existing worker requests via injected deps. */
export async function runFocusedFill(target: FocusedTarget, deps: FocusedFillDeps): Promise<void> {
  if (target.kind === 'none') { deps.notify(NOTICE_FOCUS); return; }

  if (target.kind === 'login') {
    const frameUrl = deps.frameUrl();
    const cands = await deps.loginCandidates(frameUrl);
    if (!cands.ok) { deps.notify(cands.message); return; }
    if (cands.data.length === 0) { deps.notify('No matching logins'); return; }
    if (cands.data.length > 1) { deps.openPicker(target.form.id); return; }
    const creds = await deps.loginCredentials(cands.data[0]!.id, frameUrl);
    if (!creds.ok) { deps.notify(creds.message); return; }
    if (deps.frameUrl() !== frameUrl || !loginFormLive(target.form)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    deps.fillLogin(target.form, creds.data);
    return;
  }

  const kind = target.kind; // 'card' | 'identity'
  const items = await deps.fillItems(kind);
  if (!items.ok) { deps.notify(items.message); return; }
  if (items.data.length === 0) { deps.notify(kind === 'card' ? 'No saved cards' : 'No saved identities'); return; }
  if (items.data.length > 1) { deps.openPicker(target.form.id); return; }
  const data = await deps.fillData(items.data[0]!.id, kind);
  if (!data.ok) { deps.notify(data.message); return; }
  if (!fillFormLive(target.form)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
  if (kind === 'card') deps.fillCard(target.form, data.data as CardFillData);
  else deps.fillIdentity(target.form, data.data as IdentityFillData);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/content/focused-fill.test.ts && npm run typecheck`
Expected: PASS (all suites), typecheck clean.

- [ ] **Step 5: Commit**

```bash
git add src/content/focused-fill.ts src/content/focused-fill.test.ts
git commit -m "feat: runFocusedFill orchestrator with injected deps"
```

---

### Task 5: Content wiring — protocol type, registry, `handleFocusedFill`

**Files:**
- Modify: `src/messaging/protocol.ts` (add `FocusedFillCommand` to `ContentCommand`)
- Modify: `src/content/autofill.ts` (registry, `openPickerFor`, `focusedFillDeps`, `handleFocusedFill`, command routing)
- Test: `src/content/autofill.test.ts`

**Interfaces:**
- Consumes: `resolveFocusedFill`, `runFocusedFill`, `FocusedFillDeps` (Tasks 2/4); `AutofillPopover.open()` (Task 3); existing `sendRequest`, `messageForError`, `showNotice`, `fillLoginForm/fillCardForm/fillIdentityForm`, guards `isAutofillCandidates/isAutofillCredentials/isFillItemCandidates/isFillData`.
- Produces (exported for tests): `openPickerFor(getFrameUrl, formId)`, `handleFocusedFill(getFrameUrl?)`, `popoverRegistry` (Map).

- [ ] **Step 1: Write the failing tests**

First extend the `./popover.js` mock in `src/content/autofill.test.ts` so fake popovers expose `open` and get registered — in the `vi.mock('./popover.js', …)` factory add `open: vi.fn()` to the returned `popover` object (alongside `showStatus`/`showCandidates`/`remove`), and add `open: ReturnType<typeof vi.fn>;` to the `FakePopover` interface. Also extend the `./fill-card-identity.js` mock (add if absent): `vi.mock('./fill-card-identity.js', () => ({ fillCardForm: vi.fn(), fillIdentityForm: vi.fn() }));`.

Then append a new suite:

```ts
import { handleFocusedFill, openPickerFor, popoverRegistry } from './autofill.js';

describe('focused-fill command', () => {
  beforeEach(() => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    popoverRegistry.clear();
    vi.mocked(sendRequest).mockReset();
  });

  it('does nothing when the frame is not focused', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(false);
    await handleFocusedFill(() => 'https://ex.com');
    expect(sendRequest).not.toHaveBeenCalled();
  });

  it('does nothing (no notice) when the active element is a nested frame', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    const iframe = document.createElement('iframe');
    document.body.append(iframe);
    iframe.focus();
    vi.spyOn(document, 'activeElement', 'get').mockReturnValue(iframe);
    await handleFocusedFill(() => 'https://ex.com');
    expect(sendRequest).not.toHaveBeenCalled();
  });

  it('fills a login when the focused password field has one match', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.querySelector<HTMLInputElement>('input[type="password"]')!.focus();
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: [{ id: 'c1', name: 'A', username: 'u', matchedUri: 'x', matchType: 0, favorite: false }] } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { username: 'u', password: 'p' } } as ResponseMessage);
    await handleFocusedFill(() => 'https://ex.com');
    expect(vi.mocked(fillLoginForm)).toHaveBeenCalledTimes(1);
  });

  it('openPickerFor opens a registered, connected popover', () => {
    const el = document.createElement('div');
    document.documentElement.append(el);
    const open = vi.fn();
    popoverRegistry.set('f1', { element: el, open } as never);
    openPickerFor(() => 'https://ex.com', 'f1');
    expect(open).toHaveBeenCalledTimes(1);
  });

  it('openPickerFor notices when no popover can be found after re-attach', () => {
    openPickerFor(() => 'https://ex.com', 'missing');
    expect(vi.mocked(showNotice)).toHaveBeenCalledWith("Multiple matches — click the field's Vaultwarden icon to choose");
  });
});
```

Add the needed mocks/imports at the top of the file if not already present: `vi.mock('./notice.js', () => ({ showNotice: vi.fn() }));` and `import { showNotice } from './notice.js';` and `import { fillCardForm, fillIdentityForm } from './fill-card-identity.js';`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/content/autofill.test.ts`
Expected: FAIL — `handleFocusedFill` / `openPickerFor` / `popoverRegistry` not exported.

- [ ] **Step 3: Add `FocusedFillCommand` to the protocol**

In `src/messaging/protocol.ts`, near `FillCommand`/`FillErrorCommand`:

```ts
export interface FocusedFillCommand {
  type: 'autofill.focusedFill';
}
```

Update the union:

```ts
export type ContentCommand = FillCommand | FillErrorCommand | FocusedFillCommand;
```

- [ ] **Step 4: Add registry, wiring, and handler in `autofill.ts`**

Add imports:

```ts
import { resolveFocusedFill, runFocusedFill, type FocusedFillDeps } from './focused-fill.js';
import { fillCardForm, fillIdentityForm } from './fill-card-identity.js';
import type { FocusedFillCommand } from '../messaging/protocol.js';
```

(If `fillCardForm`/`fillIdentityForm` are already imported for the existing fill flows, don't duplicate.)

Add a module-level registry (near the other module-level state such as `lastContextElement`):

```ts
/** form.id → its hover popover, so the keyboard shortcut can open the right picker on a multi-match. */
export const popoverRegistry = new Map<string, ReturnType<typeof createAutofillPopover>>();
```

Register instances in `attachPopover` and `attachFillPopover` — after each sets `popover.element.dataset.vwPopoverFor = form.id;`, add:

```ts
  popoverRegistry.set(form.id, popover);
```

Add the picker opener, deps factory, and handler (place after `handleContentCommand`):

```ts
export function openPickerFor(getFrameUrl: FrameUrlProvider, formId: string): void {
  let pop = popoverRegistry.get(formId);
  if (pop && pop.element.isConnected) { pop.open(); return; }
  popoverRegistry.delete(formId);
  attachPopovers(getFrameUrl); // idempotent (attachIfNew de-dupes) — re-attach for the current form
  pop = popoverRegistry.get(formId);
  if (pop && pop.element.isConnected) pop.open();
  else showNotice("Multiple matches — click the field's Vaultwarden icon to choose");
}

function focusedFillDeps(getFrameUrl: FrameUrlProvider): FocusedFillDeps {
  return {
    frameUrl: () => getFrameUrl(),
    loginCandidates: async (frameUrl) => {
      const r = await sendRequest({ type: 'autofill.findCandidates', frameUrl });
      if (!r.ok) return { ok: false, message: messageForError(r.error.code, r.error.message) };
      return Array.isArray(r.data) && isAutofillCandidates(r.data) ? { ok: true, data: r.data } : { ok: false, message: 'Unexpected autofill response' };
    },
    loginCredentials: async (cipherId, frameUrl) => {
      const r = await sendRequest({ type: 'autofill.getCredentials', cipherId, frameUrl });
      if (!r.ok) return { ok: false, message: messageForError(r.error.code, r.error.message) };
      return isAutofillCredentials(r.data) ? { ok: true, data: r.data } : { ok: false, message: 'Unexpected autofill response' };
    },
    fillItems: async (kind) => {
      const r = await sendRequest({ type: 'autofill.findFillItems', kind });
      if (!r.ok) return { ok: false, message: messageForError(r.error.code, r.error.message) };
      return Array.isArray(r.data) && isFillItemCandidates(r.data) ? { ok: true, data: r.data } : { ok: false, message: 'Unexpected autofill response' };
    },
    fillData: async (cipherId, kind) => {
      const r = await sendRequest({ type: 'autofill.getFillData', cipherId, kind });
      if (!r.ok) return { ok: false, message: messageForError(r.error.code, r.error.message) };
      return isFillData(r.data) ? { ok: true, data: r.data } : { ok: false, message: 'Unexpected autofill response' };
    },
    fillLogin: (form, creds) => { fillLoginForm(form, creds); },
    fillCard: (form, data) => { fillCardForm(form, data); },
    fillIdentity: (form, data) => { fillIdentityForm(form, data); },
    openPicker: (formId) => openPickerFor(getFrameUrl, formId),
    notify: (message) => showNotice(message),
  };
}

export async function handleFocusedFill(getFrameUrl: FrameUrlProvider = () => window.location.href): Promise<void> {
  if (!document.hasFocus()) return;                                   // non-focused frame
  const el = document.activeElement;
  if (el instanceof HTMLIFrameElement || el instanceof HTMLFrameElement) return; // ancestor frame — focus is in a child
  const target = resolveFocusedFill(el, document);
  await runFocusedFill(target, focusedFillDeps(getFrameUrl));
}
```

Route the command — in `handleContentCommand`, add as the FIRST branch (before the `autofill.fillError` check, so the later `command.scope` access stays type-sound):

```ts
  if (command.type === 'autofill.focusedFill') { void handleFocusedFill(); return; }
```

And in `isContentCommand`, add after the `isRecord` guard:

```ts
  if (value.type === 'autofill.focusedFill') return true;
```

- [ ] **Step 5: Run tests + typecheck to verify they pass**

Run: `npx vitest run src/content/autofill.test.ts && npm run typecheck`
Expected: PASS. If `fillItemCandidates`/guard names differ, use the exact existing guard names in `autofill.ts` (`isFillItemCandidates`, `isFillData`, `isAutofillCandidates`, `isAutofillCredentials`).

- [ ] **Step 6: Commit**

```bash
git add src/messaging/protocol.ts src/content/autofill.ts src/content/autofill.test.ts
git commit -m "feat: wire focused-fill command in content script (registry, handler, routing)"
```

---

### Task 6: Background command relay + listener

**Files:**
- Create: `src/background/commands.ts`
- Create: `src/background/commands.test.ts`
- Modify: `src/background/index.ts` (register `commands.onCommand`)

**Interfaces:**
- Consumes: `FocusedFillCommand` (Task 5).
- Produces: `FOCUSED_FILL_COMMAND` constant; `handleFocusedFillCommand(command, tab, deps)`.

- [ ] **Step 1: Write the failing test**

Create `src/background/commands.test.ts`:

```ts
import { describe, expect, it, vi } from 'vitest';
import { handleFocusedFillCommand, FOCUSED_FILL_COMMAND } from './commands.js';

function deps() {
  return { tabs: { sendMessage: vi.fn().mockResolvedValue(undefined) } };
}

describe('handleFocusedFillCommand', () => {
  it('relays the focused-fill command to the active tab', async () => {
    const d = deps();
    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, { id: 7 }, d);
    expect(d.tabs.sendMessage).toHaveBeenCalledWith(7, { type: 'autofill.focusedFill' });
  });

  it('ignores other command names', async () => {
    const d = deps();
    await handleFocusedFillCommand('something-else', { id: 7 }, d);
    expect(d.tabs.sendMessage).not.toHaveBeenCalled();
  });

  it('ignores calls without a valid tab id', async () => {
    const d = deps();
    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, undefined, d);
    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, {}, d);
    expect(d.tabs.sendMessage).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/background/commands.test.ts`
Expected: FAIL — module `./commands.js` not found.

- [ ] **Step 3: Create `src/background/commands.ts`**

```ts
import type { FocusedFillCommand } from '../messaging/protocol.js';

export const FOCUSED_FILL_COMMAND = 'autofill-focused';

export interface CommandDeps {
  tabs: { sendMessage(tabId: number, message: FocusedFillCommand): Promise<unknown> };
}

/**
 * Relay a browser keyboard command to the active tab's content scripts. The message carries no vault
 * data; the focused leaf frame decides what (if anything) to fill.
 */
export async function handleFocusedFillCommand(
  command: string,
  tab: { id?: number } | undefined,
  deps: CommandDeps,
): Promise<void> {
  if (command !== FOCUSED_FILL_COMMAND) return;
  if (typeof tab?.id !== 'number') return;
  await deps.tabs.sendMessage(tab.id, { type: 'autofill.focusedFill' });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/background/commands.test.ts`
Expected: PASS.

- [ ] **Step 5: Register the listener in `index.ts`**

In `src/background/index.ts`, add the import:

```ts
import { handleFocusedFillCommand } from './commands.js';
```

Add near the other `browser.*.addListener` registrations (e.g. after the `contextMenus.onClicked` listener):

```ts
browser.commands.onCommand.addListener((command, tab) => {
  void handleFocusedFillCommand(command, tab, {
    tabs: { sendMessage: (tabId, message) => browser.tabs.sendMessage(tabId, message) },
  });
});
```

- [ ] **Step 6: Verify full suite + typecheck + build**

Run: `npm test && npm run typecheck && npm run build`
Expected: all green; build emits `background.js` with the new listener.

- [ ] **Step 7: Commit**

```bash
git add src/background/commands.ts src/background/commands.test.ts src/background/index.ts
git commit -m "feat: relay autofill-focused keyboard command from background to content"
```

---

## Manual smoke test (after Task 6)

Load the unpacked build, confirm the shortcut at `chrome://extensions/shortcuts` (or set one if the default conflicts), then on a real page:
1. Focus a login password field on a site with one saved match → shortcut fills username+password.
2. Focus a field on a site with multiple matches → shortcut opens the popover picker at that field.
3. Focus a card number field (checkout page) with exactly one saved card → fills the card; with two+ cards → picker opens.
4. Focus an address field with one saved identity → fills; SSN/passport/license never page-filled.
5. Focus inside a nested iframe field → only that frame fills; no stray "Focus a field" notice from the parent.
6. Focus a non-form field (e.g. a search box) → notice: "Focus a login, card, or identity field, then use the shortcut".
7. A reprompt-protected item → notice: "Protected item — open the extension to verify"; secret not released inline.

---

## Self-Review Notes

- **Spec coverage:** §2 command (T1), §3.2 frame routing + §3.3 trust (T5 `handleFocusedFill` guards + T6 relay), §5.1 `computeFillExclusion` (T2), §5.2 `resolveFocusedFill` (T2), §6 all file changes (T1/T5/T6), §7 `handleFocusedFill`/`runFocusedFill` (T4/T5), §7.1 `openPickerFor` (T5), §7.2 single-vs-multi semantics (T4 tests), §8 notices (T4 constants + literals), §9 test plan (each task's tests), §10 boundaries (documented; Shadow-DOM/contenteditable resolve to `none` via T2's input/select guard). All spec sections map to a task.
- **Type consistency:** `FocusedTarget`, `FillOutcome<T>`, `FocusedFillDeps` defined in Task 2/4 and consumed unchanged in Task 5; `FocusedFillCommand` defined in Task 5 and consumed in Task 6; guard names (`isAutofillCandidates`, `isAutofillCredentials`, `isFillItemCandidates`, `isFillData`) referenced match `autofill.ts`.
- **No placeholders:** every code + test step contains complete content.
