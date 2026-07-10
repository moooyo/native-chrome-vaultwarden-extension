# Lit UI Redesign and Contextual Fill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace every extension UI surface with one original Lit 3 component system and add secure current-tab Suggestions with direct top-frame and iframe Fill.

**Architecture:** Build the Lit components beside the active imperative UI, test them in isolation, and keep the existing entry points in service until the final task switches every surface atomically. A new background `TabAutofillCoordinator` obtains browser-authoritative frame URLs, requests non-secret form metadata from content scripts, and routes credentials directly from the worker to the selected frame so popup state never receives them.

**Tech Stack:** TypeScript 6, Lit 3.3.3, MV3 service worker and content scripts, webextension-polyfill, esbuild, Vitest 4 with per-file happy-dom, Playwright 1.61.1 with Chromium.

## Global Constraints

- Use `lit@^3.3.3` as the only UI framework. Do not add React, Preact, a router, a state library, or a CSS framework.
- Use `@playwright/test@^1.61.1` only as a development dependency.
- Keep old popup, Options, Receive, and content-surface entry points active until Task 14. Tasks 1-13 may add tested modules and dormant routing, but must not deliver a mixed old/new UI.
- The final UI palette is `#3267E3` primary, `#2454C6` deep interactive, `#F4F7FF` selected, `#E7EEFF` stronger tint, `#F6F8FB` canvas, `#FFFFFF` panel, `#172033` primary text, `#677286` secondary text, and `#DCE2EB` border.
- Use 8 px control, 10 px grouped-surface, and 14 px popup-shell radii. The popup width is `25.25rem` (404 CSS px at a 16 px root) capped at `100vw`.
- Use the native UI stack with `Segoe UI Variable` first where available; keep credential values in the existing monospace stack. Do not use 1Password assets, Agile Sans, exact brand colors, CSS, or source.
- Do not use Lit `unsafeHTML` or `unsafeSVG` for page-controlled or vault-controlled content. Render values through Lit bindings or `textContent`.
- Extension pages may use ordinary Lit shadow roots. Every page-facing surface remains inside a host created with `attachShadow({ mode: 'closed' })`.
- Keep `Event.isTrusted` at every page-facing privileged click boundary.
- Direct Fill must never place credentials in popup properties, events, response data, DOM, logs, or test snapshots. Credentials travel worker/background to the selected content frame only.
- Background code derives tab, frame, document, and URL data from browser APIs. Never accept an authoritative URL from popup input.
- Re-check URI matching, reprompt, current frame URL, form identity, and connected fields at Fill commit time. Never submit a form.
- Expected async states are explicit discriminated unions. Do not add broad catches, `any`, double assertions, or success-shaped fallback data.
- Preserve all existing auth, vault CRUD, folders, collections, attachments, TOTP, generator, health/HIBP, Sends, account, PIN, password/KDF/key-rotation, import/export, Receive, save, notice, and passkey behavior.
- Argon2id remains intentionally unsupported and out of scope.
- Every UI state must be keyboard reachable, retain visible focus, meet the specified contrast, respect dark mode and reduced motion, and avoid document-level horizontal overflow at 320 CSS px.
- Every commit command in this plan must include `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`.

---

## File Structure

### Shared component system

- `src\ui\components\tokens.ts`: top-level light/dark custom properties.
- `src\ui\components\styles.ts`: reusable native button, field, focus, and typography CSS.
- `src\ui\components\icon.ts`: Lit-safe, static SVG templates and `IconName`.
- `src\ui\components\async-state.ts`: shared `AsyncState<T>` union.
- `src\ui\components\status-message.ts`: live success/error/status output.
- `src\ui\components\menu.ts`: typed keyboard menu and selection event.
- `src\ui\components\tabs.ts`: typed tab list and keyboard selection.
- `src\ui\components\dialog.ts`: modal focus lifecycle and cancellation event.
- `src\ui\components\page-shell.ts`: settings rail and no-rail full-page shell.

### Contextual Suggestions and Fill

- `src\content\frame-autofill.ts`: per-frame inspection, focus metadata, target validation, and commit.
- `src\background\tab-autofill.ts`: browser-frame orchestration, ranking, URI-safe candidate merge, and direct Fill.
- `src\messaging\protocol.ts`: typed popup/background/content messages and outcomes.
- `src\content\autofill.ts`: final registration of frame inspection/commit handlers.
- `src\background\router.ts`, `src\background\index.ts`: coordinator routing and browser adapters.
- `src\manifest.json`: final `activeTab` and `webNavigation` permissions.

### Popup

- `src\ui\popup\app.ts`: root route/state machine, request orchestration, and secret cleanup.
- `src\ui\popup\types.ts`: routes, events, browser adapter, and popup-specific state.
- `src\ui\popup\auth\auth-views.ts`: login, register, 2FA, unlock, PIN, and remembered-device UI.
- `src\ui\popup\vault\popup-header.ts`: account/add/generator/tools controls.
- `src\ui\popup\vault\vault-view.ts`: Suggestions/All items tabs and loading/error states.
- `src\ui\popup\vault\suggestions-view.ts`: current-tab candidates and Fill results.
- `src\ui\popup\vault\all-items-view.ts`: search, filters, trash, and item list.
- `src\ui\popup\vault\vault-filters.ts`: folder/collection selection and mutations.
- `src\ui\popup\vault\vault-item-row.ts`: shared non-secret item row.
- `src\ui\popup\menus\account-menu.ts`: account, PIN, account security, settings, lock, logout.
- `src\ui\popup\menus\tools-menu.ts`: health, Sends, trash, and sync.
- `src\ui\popup\item\item-detail.ts`: four cipher details, custom fields, history, and actions.
- `src\ui\popup\item\secret-field.ts`: explicit reveal/copy control.
- `src\ui\popup\item\totp-field.ts`: current code and timer cleanup.
- `src\ui\popup\item\attachment-list.ts`: download/upload/delete UI.
- `src\ui\popup\editor\item-editor.ts`: create/edit orchestration.
- `src\ui\popup\editor\cipher-fields.ts`: login/note/card/identity fields and URI rows.
- `src\ui\popup\editor\custom-fields-editor.ts`: Text/Hidden/Boolean field rows.
- `src\ui\popup\editor\collection-picker.ts`: collection assignments and organization move.
- `src\ui\popup\tools\generator-view.ts`: password/passphrase/username generator and in-memory history.
- `src\ui\popup\tools\health-view.ts`: local health and on-demand HIBP.
- `src\ui\popup\tools\sends-view.ts`: text/file create, edit, list, copy, receive, and delete.
- `src\ui\popup\tools\account-security-view.ts`: master password, PBKDF2, and key rotation.
- `src\ui\popup\tools\pin-view.ts`: set/remove PIN.
- `src\ui\popup\utils.ts`: URL validation, copy scheduling, files, TOTP formatting, monograms.

### Full pages and content surfaces

- `src\ui\options\options-app.ts` and `src\ui\options\sections\*.ts`: rail sections and Data import/export.
- `src\ui\receive\receive-app.ts`: Send access state machine with injectable browser/fetch/download dependencies.
- `src\content\ui\closed-surface.ts`: closed-root mount helper retaining the internal root reference.
- `src\content\ui\autofill-popover-element.ts`
- `src\content\ui\save-bar-element.ts`
- `src\content\ui\notice-element.ts`
- `src\content\ui\passkey-dialog-element.ts`
- `src\content\surface-position.ts`: viewport-clamped pure positioning.

### Rendered test harness

- `tools\build-ui-fixtures.mjs`: bundle deterministic fixture entry into ignored `dist\ui-test`.
- `test\ui-render\fixture-entry.ts`: mount requested component/state from query parameters.
- `test\ui-render\fixture.html`: browser host page.
- `test\ui-render\server.mjs`: local static server for Playwright.
- `test\ui-render\layout.spec.ts`, `keyboard.spec.ts`, `accessibility.spec.ts`, `visual.spec.ts`
- `playwright.config.ts`

---

### Task 1: Install Lit and Create the Token Foundation

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `src\ui\components\tokens.ts`
- Create: `src\ui\components\styles.ts`
- Create: `src\ui\components\icon.ts`
- Create: `src\ui\components\async-state.ts`
- Test: `src\ui\components\tokens.test.ts`
- Test: `src\ui\components\icon.test.ts`

**Interfaces:**
- Produces: `themeTokens`, `controlStyles`, `type IconName`, `uiIcon(name: IconName)`, and `AsyncState<T>`.
- Consumed by: every later Lit component.

- [ ] **Step 1: Install the approved dependencies**

Run:

```powershell
npm.cmd install lit@^3.3.3
npm.cmd install --save-dev @playwright/test@^1.61.1
```

Expected: `package.json` contains `lit` under `dependencies`, `@playwright/test` under `devDependencies`, and the lockfile resolves Lit 3.3.3 and Playwright 1.61.1 or compatible patch releases.

- [ ] **Step 2: Write failing token and icon tests**

Create `src\ui\components\tokens.test.ts` and `src\ui\components\icon.test.ts`:

```ts
// @vitest-environment happy-dom
import { describe, expect, it } from 'vitest';
import { render } from 'lit';
import { themeTokens } from './tokens.js';
import { uiIcon } from './icon.js';

describe('UI foundation', () => {
  it('pins the approved blue and geometry tokens', () => {
    const css = themeTokens.cssText;
    expect(css).toContain('--vw-blue-600:#3267e3');
    expect(css).toContain('--vw-canvas:#f6f8fb');
    expect(css).toContain('--vw-radius-shell:14px');
    expect(css).toContain('prefers-color-scheme:dark');
    expect(css).toContain('prefers-reduced-motion:reduce');
  });

  it('renders static SVG without unsafe HTML', () => {
    const host = document.createElement('div');
    render(uiIcon('shield'), host);
    expect(host.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
    expect(host.querySelector('path')).not.toBeNull();
  });
});
```

- [ ] **Step 3: Run the tests and verify the missing modules fail**

Run:

```powershell
npm.cmd test -- src\ui\components\tokens.test.ts src\ui\components\icon.test.ts
```

Expected: FAIL because `tokens.ts` and `icon.ts` do not exist.

- [ ] **Step 4: Implement the token, base-style, icon, and async-state modules**

Use this public shape:

```ts
// src/ui/components/async-state.ts
export type AsyncState<T> =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'ready'; data: T }
  | { status: 'empty' }
  | { status: 'error'; message: string };
```

```ts
// src/ui/components/tokens.ts
import { css } from 'lit';

export const themeTokens = css`
  :host {
    --vw-blue-800: #193f9e;
    --vw-blue-700: #2454c6;
    --vw-blue-600: #3267e3;
    --vw-blue-200: #cddaff;
    --vw-blue-100: #e7eeff;
    --vw-blue-50: #f4f7ff;
    --vw-canvas: #f6f8fb;
    --vw-panel: #fff;
    --vw-ink: #172033;
    --vw-muted: #677286;
    --vw-line: #dce2eb;
    --vw-ok: #187a59;
    --vw-danger: #b33b46;
    --vw-radius-control: 8px;
    --vw-radius-group: 10px;
    --vw-radius-shell: 14px;
    --vw-focus: 0 0 0 3px rgb(50 103 227 / 28%);
    --vw-font-ui: "Segoe UI Variable", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    --vw-font-mono: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
  }
  @media (prefers-color-scheme: dark) {
    :host {
      --vw-canvas: #0f1420;
      --vw-panel: #171e2b;
      --vw-ink: #edf2fb;
      --vw-muted: #a9b3c4;
      --vw-line: #303a4c;
      --vw-blue-50: #182544;
      --vw-blue-100: #21345f;
      --vw-blue-200: #395a9e;
      --vw-blue-600: #79a2ff;
      --vw-blue-700: #9ab9ff;
      --vw-focus: 0 0 0 3px rgb(121 162 255 / 38%);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    :host { --vw-duration: 0ms; }
  }
`;
```

In `styles.ts`, export `controlStyles` with native `.button`, `.icon-button`, `.field`, `.input`, `.select`, `.mono`, and `:focus-visible` rules using only the variables above. In `icon.ts`, move the static paths from `src\ui\icons.ts` into a typed `Record<IconName, ReturnType<typeof svg>>` and return SVG templates through Lit's `svg` tag.

- [ ] **Step 5: Run the foundation tests and typecheck**

Run:

```powershell
npm.cmd test -- src\ui\components\tokens.test.ts src\ui\components\icon.test.ts
npm.cmd run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add package.json package-lock.json src\ui\components && git commit -m "feat: add Lit UI foundation" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Build Keyboard-Safe Shared Components

**Files:**
- Create: `src\ui\components\status-message.ts`
- Create: `src\ui\components\menu.ts`
- Create: `src\ui\components\tabs.ts`
- Create: `src\ui\components\dialog.ts`
- Create: `src\ui\components\page-shell.ts`
- Test: matching `*.test.ts` files beside each component

**Interfaces:**
- Produces: `VwStatusMessage`, `VwMenu`, `VwTabs`, `VwDialog`, and `VwPageShell`.
- Events: `vw-menu-select`, `vw-menu-close`, `vw-tab-change`, and `vw-dialog-close`.

- [ ] **Step 1: Write failing interaction tests**

Use typed items and verify keyboard behavior:

```ts
// @vitest-environment happy-dom
import { describe, expect, it, vi } from 'vitest';
import './menu.js';
import './tabs.js';

it('moves menu focus and selects the active item', async () => {
  const menu = document.createElement('vw-menu') as import('./menu.js').VwMenu;
  menu.items = [
    { id: 'health', label: 'Password Health' },
    { id: 'sync', label: 'Sync' },
  ];
  menu.open = true;
  const selected = vi.fn();
  menu.addEventListener('vw-menu-select', selected);
  document.body.append(menu);
  await menu.updateComplete;
  menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
  menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
  expect(selected).toHaveBeenCalledWith(expect.objectContaining({
    detail: { id: 'sync' },
  }));
});

it('changes tabs with ArrowRight and Home', async () => {
  const tabs = document.createElement('vw-tabs') as import('./tabs.js').VwTabs;
  tabs.tabs = [{ id: 'suggestions', label: 'Suggestions' }, { id: 'all', label: 'All items' }];
  tabs.selected = 'suggestions';
  document.body.append(tabs);
  await tabs.updateComplete;
  tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
  expect(tabs.selected).toBe('all');
  tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home', bubbles: true }));
  expect(tabs.selected).toBe('suggestions');
});
```

Add dialog tests for Escape, initial focus, focus restoration, and non-cancelable destructive mode. Add page-shell tests for rail mode and the narrow top-selector mode class.

- [ ] **Step 2: Run the tests and verify failure**

```powershell
npm.cmd test -- src\ui\components\status-message.test.ts src\ui\components\menu.test.ts src\ui\components\tabs.test.ts src\ui\components\dialog.test.ts src\ui\components\page-shell.test.ts
```

Expected: FAIL because the elements are not registered.

- [ ] **Step 3: Implement typed component contracts**

Use these exported types:

```ts
export interface MenuItem {
  id: string;
  label: string;
  icon?: import('./icon.js').IconName;
  tone?: 'normal' | 'danger';
  disabled?: boolean;
}

export interface TabItem {
  id: string;
  label: string;
  count?: number;
}

export interface SettingsRailItem {
  id: string;
  label: string;
  icon: import('./icon.js').IconName;
}
```

Each component must:

- use native controls and roles inside its shadow root;
- include `themeTokens` and `controlStyles`;
- expose properties through `static properties`, not decorators;
- dispatch composed, bubbling `CustomEvent`s with the exact names above;
- remove document-level key/focus listeners in `disconnectedCallback`;
- never render a caller-provided HTML string.

- [ ] **Step 4: Run focused tests, typecheck, and lint**

```powershell
npm.cmd test -- src\ui\components
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src\ui\components && git commit -m "feat: add accessible Lit UI primitives" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Define Frame Inspection and Commit Fill

**Files:**
- Modify: `src\messaging\protocol.ts`
- Create: `src\content\frame-autofill.ts`
- Test: `src\content\frame-autofill.test.ts`

**Interfaces:**
- Produces: `FrameInspection`, `FrameLoginForm`, `TabSuggestionTarget`, `TabAutofillSuggestion`, `TabSuggestionsOutcome`, `TabFillOutcome`, `FrameAutofillMessage`, and `createFrameAutofillController`.
- Reuses: `detectLoginForms`, `fillLoginForm`, `AutofillCandidate`, and `AutofillCredentials`.

- [ ] **Step 1: Add failing tests for metadata-only inspection and TOCTOU**

```ts
// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { createFrameAutofillController } from './frame-autofill.js';

describe('frame autofill controller', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <form><input name="email" type="email"><input type="password"></form>`;
  });

  it('returns form metadata without field values', () => {
    const email = document.querySelector<HTMLInputElement>('input[type=email]')!;
    email.value = 'must-not-cross';
    const controller = createFrameAutofillController({
      root: document,
      frameUrl: () => 'https://login.example.com/',
      now: () => 1000,
    });
    controller.noteFocus(email);
    const inspection = controller.inspect();
    expect(inspection.frameUrl).toBe('https://login.example.com/');
    expect(inspection.forms).toHaveLength(1);
    expect(JSON.stringify(inspection)).not.toContain('must-not-cross');
    expect(inspection.forms[0]?.focusedAt).toBe(1000);
  });

  it('fails closed when URL or form identity changes', () => {
    let url = 'https://example.com/login';
    const controller = createFrameAutofillController({
      root: document,
      frameUrl: () => url,
      now: () => 0,
    });
    const target = controller.inspect().forms[0]!;
    url = 'https://evil.example/';
    expect(controller.commit({
      formId: target.formId,
      expectedFrameUrl: 'https://example.com/login',
      credentials: { username: 'u', password: 'p' },
    })).toEqual({ status: 'target_changed' });
  });
});
```

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\content\frame-autofill.test.ts
```

Expected: FAIL because `frame-autofill.ts` does not exist.

- [ ] **Step 3: Add exact protocol types**

Append these shapes to `protocol.ts` and extend its request/response unions:

```ts
export interface FrameLoginForm {
  formId: string;
  visible: boolean;
  focusedAt?: number;
}

export interface FrameInspection {
  frameUrl: string;
  forms: FrameLoginForm[];
}

export interface TabSuggestionTarget {
  frameId: number;
  formId: string;
  documentId?: string;
}

export interface TabAutofillSuggestion extends AutofillCandidate {
  target?: TabSuggestionTarget;
}

export type TabSuggestionsOutcome =
  | { status: 'ready'; suggestions: TabAutofillSuggestion[] }
  | {
      status:
        | 'no_eligible_tab'
        | 'site_access_unavailable'
        | 'restricted_page'
        | 'content_script_unavailable';
      suggestions: [];
    };

export type TabFillOutcome =
  | { status: 'filled' }
  | { status: 'no_eligible_tab' }
  | { status: 'site_access_unavailable' }
  | { status: 'no_fillable_target' }
  | { status: 'target_changed' }
  | { status: 'restricted_page' }
  | { status: 'content_script_unavailable' };

export type FrameAutofillMessage =
  | { type: 'autofill.inspectFrame' }
  | {
      type: 'autofill.commitLoginFill';
      formId: string;
      expectedFrameUrl: string;
      credentials: AutofillCredentials;
    };
```

Add requests:

```ts
| { type: 'autofill.getTabSuggestions'; tabId: number }
| { type: 'autofill.fillTabSuggestion'; tabId: number; cipherId: string; target: TabSuggestionTarget }
```

Add successful response data for `{ outcome: TabSuggestionsOutcome }` and `{ outcome: TabFillOutcome }`.

- [ ] **Step 4: Implement the controller**

`createFrameAutofillController` must retain only `lastFocusedFormId` and `focusedAt`, re-run `detectLoginForms` for every inspect/commit, compare `frameUrl()` to `expectedFrameUrl`, verify at least one connected fillable field, call `fillLoginForm`, and return `{ status: 'filled' }` only when that function returns true.

- [ ] **Step 5: Run focused tests and protocol typecheck**

```powershell
npm.cmd test -- src\content\frame-autofill.test.ts src\content\form-detection.test.ts src\content\fill.test.ts
npm.cmd run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src\messaging\protocol.ts src\content\frame-autofill.ts src\content\frame-autofill.test.ts && git commit -m "feat: add frame-safe login fill inspection" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: Add the Background Tab Autofill Coordinator

**Files:**
- Create: `src\background\tab-autofill.ts`
- Test: `src\background\tab-autofill.test.ts`
- Modify: `src\background\router.ts`
- Modify: `src\background\router.test.ts`
- Modify: `src\background\index.ts`
- Modify: `src\manifest.json`
- Modify: `src\manifest.test.ts`

**Interfaces:**
- Consumes: Task 3 protocol types and existing `VaultService.findAutofillCandidates` / `getAutofillCredentials`.
- Produces: `createTabAutofillCoordinator(deps)` with `getSuggestions(tabId): Promise<TabSuggestionsOutcome>` and `fill(tabId, cipherId, target): Promise<TabFillOutcome>`.

- [ ] **Step 1: Write failing coordinator and manifest tests**

Cover:

```ts
it('prefers focus newer than 30 seconds, then top frame, then document order');
it('deduplicates a cipher and keeps its best fill target');
it('keeps top-frame URI matches without a Fill target when no form exists');
it('returns no credentials in suggestion JSON');
it('skips one unavailable content frame but reports unavailable when all frames fail');
it('re-reads the frame URL before decrypting credentials');
it('sends credentials only to the selected frame and returns its typed outcome');
it('rejects a changed documentId before credential release');
it('declares activeTab and webNavigation permissions');
```

The security assertion must be explicit:

```ts
const suggestions = await coordinator.getSuggestions(7);
expect(JSON.stringify(suggestions)).not.toMatch(/password|totp|credentials/i);
expect(getCredentials).not.toHaveBeenCalled();
```

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\background\tab-autofill.test.ts src\manifest.test.ts
```

Expected: FAIL because the coordinator and permissions do not exist.

- [ ] **Step 3: Implement narrow browser adapters and ranking**

Use this dependency boundary:

```ts
export interface BrowserFrame {
  frameId: number;
  url: string;
  documentId?: string;
}

export interface TabAutofillDeps {
  getTab(tabId: number): Promise<{ active: boolean; url?: string }>;
  hasHostAccess(url: string): Promise<boolean>;
  getFrames(tabId: number): Promise<BrowserFrame[]>;
  getFrame(tabId: number, frameId: number): Promise<BrowserFrame | undefined>;
  sendToFrame(tabId: number, frameId: number, message: FrameAutofillMessage): Promise<unknown>;
  findCandidates(frameUrl: string): Promise<AutofillCandidate[]>;
  getCredentials(cipherId: string, frameUrl: string): Promise<AutofillCredentials>;
  now(): number;
}
```

Parse `unknown` frame responses with type guards. Do not cast them. A recent focused target is one whose `focusedAt >= now() - 30_000`. Always match the eligible top-frame URL so a row can open detail without a form; merge inspected frame matches and attach a target only when one exists. Before Fill, compare current `frameId`, `url`, and optional `documentId` to the supplied target, then call `getCredentials`, then send `autofill.commitLoginFill`.

- [ ] **Step 4: Route and wire the coordinator**

Add optional `tabAutofill` methods to `RouterDeps`, add exact cases for both Task 3 requests, and instantiate the coordinator in `index.ts` with:

- `browser.tabs.get`;
- `browser.permissions.contains` through `hasHostAccess`;
- `browser.webNavigation.getAllFrames`;
- `browser.webNavigation.getFrame`;
- `browser.tabs.sendMessage` targeted by `frameId`;
- current settings strategy closures around the existing VaultService methods.

Add `"activeTab"` and `"webNavigation"` to manifest permissions.

- [ ] **Step 5: Run coordinator, router, manifest, and existing autofill tests**

```powershell
npm.cmd test -- src\background\tab-autofill.test.ts src\background\router.test.ts src\manifest.test.ts src\core\vault\vault-service.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src\background src\messaging\protocol.ts src\manifest.json src\manifest.test.ts && git commit -m "feat: coordinate secure active-tab fill" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 5: Build the Dormant Popup Root and Auth Flows

**Files:**
- Create: `src\ui\popup\types.ts`
- Create: `src\ui\popup\app.ts`
- Create: `src\ui\popup\auth\auth-views.ts`
- Test: `src\ui\popup\auth\auth-views.test.ts`
- Test: `src\ui\popup\app.test.ts`

**Interfaces:**
- `PopupRequest = typeof sendRequest`.
- `PopupBrowser.getActiveTabId()`, `openOptions()`, and `openReceive()`.
- `PopupRoute` covers loading, login, register, twoFactor, unlock, vault, detail, editor, generator, health, sends, trash, accountSecurity, and pin.

- [ ] **Step 1: Write failing state-machine and auth tests**

Test loading-to-auth-state routing, login validation, registration confirmation, all code-based 2FA providers, email code, remember-device checkbox, remembered-device revoke, password unlock, PIN unlock, and clearing secret inputs after success.

Use an injected request function:

```ts
const request: import('./types.js').PopupRequest = vi.fn(async (message) => {
  if (message.type === 'auth.getState') return { ok: true, data: { state: 'locked' } };
  return { ok: true, data: null };
});
const app = document.createElement('vw-popup-app') as import('./app.js').VwPopupApp;
app.request = request;
document.body.append(app);
await app.updateComplete;
expect(app.route.name).toBe('unlock');
```

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\ui\popup\auth\auth-views.test.ts src\ui\popup\app.test.ts
```

Expected: FAIL because the popup Lit modules do not exist.

- [ ] **Step 3: Implement exact route and dependency types**

```ts
export type PopupRoute =
  | { name: 'loading' }
  | { name: 'login'; error?: string }
  | { name: 'register'; error?: string }
  | { name: 'twoFactor'; providers: number[]; error?: string }
  | { name: 'unlock'; error?: string }
  | { name: 'vault'; scope: 'suggestions' | 'all'; error?: string }
  | { name: 'detail'; cipherId: string }
  | { name: 'editor'; mode: 'create' | 'edit'; cipherId?: string; cipherType?: 1 | 2 | 3 | 4 }
  | { name: 'generator' | 'health' | 'sends' | 'trash' | 'accountSecurity' | 'pin' };

export type PopupRequest = typeof import('../../messaging/protocol.js').sendRequest;

export interface PopupBrowser {
  getActiveTabId(): Promise<number | undefined>;
  openOptions(): Promise<void>;
  openReceive(): Promise<void>;
}
```

`VwPopupApp` owns `route`, pending state, listing state, filters, generator state, and a private non-reactive reprompt credential. `navigate()` clears the TOTP timer and reprompt credential before assigning the next route.

- [ ] **Step 4: Implement auth rendering and request orchestration**

`auth-views.ts` exports one component with `mode` and typed submit events. It never calls `sendRequest`. The root handles the exact current transitions from `popup.ts:82-423` and keeps provider names and provider restrictions unchanged.

- [ ] **Step 5: Run focused tests and typecheck**

```powershell
npm.cmd test -- src\ui\popup\auth src\ui\popup\app.test.ts src\core\session\auth-service.test.ts
npm.cmd run typecheck
```

Expected: PASS while the production popup still uses old `popup.ts`.

- [ ] **Step 6: Commit**

```powershell
git add src\ui\popup\types.ts src\ui\popup\app.ts src\ui\popup\auth && git commit -m "feat: build Lit popup auth state machine" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 6: Build Suggestions, All Items, Filters, and Menus

**Files:**
- Create all popup vault and menu files listed in File Structure
- Test: matching files plus `src\ui\popup\vault\vault-view.test.ts`
- Modify: `src\ui\popup\app.ts`

**Interfaces:**
- `vw-suggestion-fill` detail: `{ cipherId: string; target: TabSuggestionTarget }`.
- `vw-item-open` detail: `{ cipherId: string }`.
- `vw-filter-change` detail: folder/collection/query/trash patch.
- `vw-account-action` and `vw-tool-action` details use closed string unions, not arbitrary strings.

- [ ] **Step 1: Write failing UI and integration tests**

Cover:

- Suggestions is the default for an eligible active tab.
- Restricted/missing tab shows a neutral status and All items remains selectable.
- A candidate row contains no password/TOTP and Fill is absent without `target`.
- Fill sends only tab/cipher/target and renders every `TabFillOutcome`.
- All items preserves `filterSummariesByFolderCollectionAndQuery`, favorites, type labels, trash, skipped-org banner, folder CRUD, collection permission gates, and collection CRUD.
- Header/account/tools menu mappings include every approved action, including Account security.
- Menu close restores focus.

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\ui\popup\vault src\ui\popup\menus src\ui\popup\app.test.ts
```

Expected: FAIL because the view components are missing.

- [ ] **Step 3: Implement typed events and pure rendering**

Use a closed action vocabulary:

```ts
export type AccountAction =
  | 'switch-account'
  | 'remove-account'
  | 'add-account'
  | 'pin'
  | 'account-security'
  | 'options'
  | 'lock'
  | 'logout'
  | 'forget-device';

export type ToolAction = 'health' | 'sends' | 'trash' | 'sync';
```

The root performs every request and passes `AsyncState` data downward. Components dispatch events only. Keep filter/search logic in existing core helpers rather than duplicating it in Lit components.

- [ ] **Step 4: Implement Suggestions orchestration**

On unlocked load:

1. `getActiveTabId()`;
2. if defined, request `autofill.getTabSuggestions`;
3. render `outcome.suggestions` when status is `ready`, otherwise map the explicit unavailable status to neutral guidance;
4. on Fill, request `autofill.fillTabSuggestion`;
5. map `ok:false` AppErrors and `ok:true` outcomes to local status;
6. never include credentials in a component property.

- [ ] **Step 5: Run focused and search tests**

```powershell
npm.cmd test -- src\ui\popup\vault src\ui\popup\menus src\ui\popup\app.test.ts src\core\vault\search.test.ts
npm.cmd run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src\ui\popup\app.ts src\ui\popup\vault src\ui\popup\menus && git commit -m "feat: add contextual Lit vault navigation" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 7: Build Item Detail, Reprompt, TOTP, and Attachments

**Files:**
- Create all popup item files listed in File Structure
- Create: `src\ui\popup\utils.ts`
- Test: matching `*.test.ts`
- Modify: `src\ui\popup\app.ts`

**Interfaces:**
- Detail consumes `CipherSummary`, `DecryptedCipher`, optional verified reprompt credential, and explicit async extras.
- Events: `vw-secret-request`, `vw-copy`, `vw-edit-item`, `vw-delete-item`, `vw-restore-item`, `vw-attachment-download`, `vw-attachment-add`, `vw-attachment-delete`.

- [ ] **Step 1: Write failing detail tests**

Cover all current behavior from `popup.ts:2114-2699`:

- reprompt gate before protected detail/edit;
- login username/password/URI/TOTP/passkey/history/custom fields;
- secure-note body;
- card and identity plain and protected fields;
- hidden custom-field reveal;
- attachment download/upload/delete;
- safe `http:`/`https:` links only;
- copy schedules clipboard clearing;
- TOTP refresh at expiry and timer cleanup on disconnect;
- navigation clears reprompt state.

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\ui\popup\item src\ui\popup\utils.test.ts
```

Expected: FAIL because the modules do not exist.

- [ ] **Step 3: Implement safe utilities**

```ts
export function safeWebUrl(value: string): string | undefined {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.toString() : undefined;
  } catch {
    return undefined;
  }
}

export function formatTotp(code: string): string {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}
```

Copy uses `navigator.clipboard.writeText(value)` followed by `{ type: 'clipboard.scheduleClear' }`. File helpers preserve base64 conversion and object-URL revocation behavior.

- [ ] **Step 4: Implement detail orchestration**

The root requests values only after explicit reveal/copy. Before reveal, secret values must not appear in component properties or DOM. A verified reprompt password is held in one private root field only for the current cipher and is cleared on navigation, lock, account switch, logout, and disconnect.

- [ ] **Step 5: Run detail, vault-service, and TOTP tests**

```powershell
npm.cmd test -- src\ui\popup\item src\ui\popup\utils.test.ts src\core\vault\totp.test.ts src\core\vault\vault-service.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src\ui\popup\app.ts src\ui\popup\item src\ui\popup\utils.ts src\ui\popup\utils.test.ts && git commit -m "feat: add Lit vault item details" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 8: Build Cipher, Folder, Collection, and Trash Editing

**Files:**
- Create all popup editor files listed in File Structure
- Test: matching `*.test.ts`
- Modify: `src\ui\popup\app.ts`
- Modify: `src\ui\popup\vault\vault-filters.ts`

**Interfaces:**
- `vw-editor-save` detail is a complete `CipherInput`.
- `vw-folder-mutation` detail is `{ mode: 'create' | 'rename' | 'delete'; id?: string; name?: string }`.
- `vw-collection-mutation` carries organization and collection identifiers.
- Organization move and collection assignment remain separate operations.

- [ ] **Step 1: Write failing editor tests**

Pin the behavior in `popup.ts:1555-2059`:

- four cipher types;
- login username/password/TOTP/multiple URIs/per-URI match;
- secure note;
- card and identity fields;
- custom Text/Hidden/Boolean and read-only Linked fields;
- favorite, reprompt, notes, folder, collection assignments;
- attachment add/delete in edit mode;
- personal-to-organization share guard for passkey/history;
- create, update, soft delete, permanent delete, restore;
- folder/collection create/rename/delete and permission gates;
- disabled controls while pending and local error output.

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\ui\popup\editor src\ui\popup\vault\vault-filters.test.ts
```

Expected: FAIL because editor modules do not exist.

- [ ] **Step 3: Implement typed field collection**

The editor components own form-only state and emit one validated `CipherInput`. The root performs requests. Preserve exact optional-property semantics by conditionally spreading optional values rather than assigning `undefined`.

Use:

```ts
export interface EditorContext {
  mode: 'create' | 'edit';
  type: 1 | 2 | 3 | 4;
  cipherId?: string;
  input?: CipherInput;
  folders: readonly FolderSummary[];
  collections: readonly CollectionSummary[];
  orgPermissions: readonly OrgPermission[];
}
```

- [ ] **Step 4: Wire mutations through existing request messages**

Reuse `vault.createCipher`, `updateCipher`, `softDeleteCipher`, `deleteCipher`, `restoreCipher`, folder/collection routes, `vault.setCipherCollections`, `vault.shareCipher`, and attachment routes. Reload the cached listing after successful mutation and keep errors local to the active editor/filter.

- [ ] **Step 5: Run editor and core CRUD tests**

```powershell
npm.cmd test -- src\ui\popup\editor src\ui\popup\vault\vault-filters.test.ts src\core\vault\encrypt.test.ts src\core\vault\vault-service.test.ts
npm.cmd run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src\ui\popup\app.ts src\ui\popup\editor src\ui\popup\vault\vault-filters.ts src\ui\popup\vault\vault-filters.test.ts && git commit -m "feat: add Lit vault editing flows" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 9: Build Generator, Health, Sends, PIN, and Account Security

**Files:**
- Create all popup tool files listed in File Structure
- Test: matching `*.test.ts`
- Modify: `src\ui\popup\app.ts`
- Modify: `src\ui\popup\menus\account-menu.ts`
- Modify: `src\ui\popup\menus\tools-menu.ts`

**Interfaces:**
- Tools render from typed props and emit typed commands; only the popup root calls worker routes.
- Generator history remains popup-memory-only and caps through existing `addPasswordToHistory`.

- [ ] **Step 1: Write failing tool tests**

Pin current behavior from `popup.ts:909-1615`:

- password/passphrase/username modes and option limits;
- regenerate, copy, clear history, and account-email prefill;
- local health report and explicit HIBP check;
- text/file Send create, 100 MB file cap, edit password keep/set/remove, receive-page open, copy, and delete;
- PIN status/set/remove;
- account list/switch/remove/add/forget-device;
- current/new/confirm password validation;
- PBKDF2 minimum 600000;
- two-step key-rotation warning and logout-on-success;
- secret and generator state clearing on lock/logout/account switch.

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\ui\popup\tools src\ui\popup\menus
```

Expected: FAIL because the tool components do not exist.

- [ ] **Step 3: Implement tools with injected state**

Keep generator calls local to core generator functions. Sends and account security emit typed inputs to the root. Use `AsyncState` for list/report operations and a separate pending state for destructive commands.

- [ ] **Step 4: Wire exact worker routes**

Reuse all current `sends.*`, health, HIBP, auth account/PIN/password/KDF/rotation, clipboard, and tab-open routes. Do not introduce background scans or persistent generator history.

- [ ] **Step 5: Run focused and core tool tests**

```powershell
npm.cmd test -- src\ui\popup\tools src\ui\popup\menus src\core\generator src\core\vault\sends.test.ts src\core\vault\password-health.test.ts src\core\vault\pwned.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src\ui\popup\app.ts src\ui\popup\tools src\ui\popup\menus && git commit -m "feat: add Lit vault tools and security UI" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 10: Build the Dormant Options App and Move Import/Export

**Files:**
- Create: `src\ui\options\options-app.ts`
- Create: `src\ui\options\types.ts`
- Create: `src\ui\options\sections\connection-section.ts`
- Create: `src\ui\options\sections\security-section.ts`
- Create: `src\ui\options\sections\autofill-section.ts`
- Create: `src\ui\options\sections\data-section.ts`
- Create: `src\ui\options\sections\about-section.ts`
- Test: matching `*.test.ts`

**Interfaces:**
- `OptionsDeps`: `request`, `requestOrigins`, `downloadText`, and `readFile`.
- The root owns loaded settings, active rail item, session state, and per-section async status.

- [ ] **Step 1: Write failing section and root tests**

Cover:

- rail sections Connection/Security/Autofill/Data/About;
- narrow selector mode;
- normalized URL and permission request occurs synchronously in the submit gesture before other awaits;
- URI strategy help;
- lock timeout;
- save-on-change idle action/clipboard behavior;
- Data disabled while locked;
- encrypted/plaintext export confirmations and filenames;
- JSON/CSV import, encrypted-password prompt, and imported count;
- About version and local-secret statement;
- section-local errors/live status.

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\ui\options
```

Expected: FAIL because the Lit Options files do not exist.

- [ ] **Step 3: Implement the injected dependency boundary**

```ts
export interface OptionsDeps {
  request: typeof sendRequest;
  requestOrigins(origins: string[]): Promise<boolean>;
  downloadText(content: string, fileName: string): void;
  readFile(file: File): Promise<string>;
  extensionVersion(): string;
}
```

Use existing `settings.get`, `settings.save`, and `settings.saveSecurity` routes. When saving Autofill or lock timeout, include the loaded server URL required by the current `settings.save` contract without re-requesting permission. Only Connection invokes `requestOrigins`.

- [ ] **Step 4: Implement Data without popup coupling**

Move export/import orchestration from old `popup.ts:871-1072` into the Options root and Data component. Do not import popup modules. Read `auth.getState` first and render the explicit locked state.

- [ ] **Step 5: Run Options, router, and vault I/O tests**

```powershell
npm.cmd test -- src\ui\options src\background\router.test.ts src\core\vault\vault-io.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS while `options.ts` still runs the old UI.

- [ ] **Step 6: Commit**

```powershell
git add src\ui\options && git commit -m "feat: build Lit settings and data UI" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 11: Build the Dormant Receive App

**Files:**
- Create: `src\ui\receive\receive-app.ts`
- Create: `src\ui\receive\types.ts`
- Test: `src\ui\receive\receive-app.test.ts`

**Interfaces:**
- `ReceiveDeps`: `fetch`, `requestOrigin`, and `download`.
- `ReceiveState`: idle, accessing, passwordRequired, textReady, fileReady, downloading, and error.

- [ ] **Step 1: Write failing state tests**

Cover invalid link, permission denial, password-required focus, successful text, successful file metadata, download/decrypt, unavailable, decrypt failure, object URL cleanup, and double-submit prevention.

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\ui\receive\receive-app.test.ts
```

Expected: FAIL because the app does not exist.

- [ ] **Step 3: Implement exact dependencies and states**

```ts
export interface ReceiveDeps {
  fetch: typeof fetch;
  requestOrigin(originPattern: string): Promise<boolean>;
  download(bytes: Uint8Array, fileName: string): void;
}

export type ReceiveState =
  | { status: 'idle' }
  | { status: 'accessing' }
  | { status: 'passwordRequired'; message: string }
  | { status: 'textReady'; name: string; text: string }
  | { status: 'fileReady'; parsed: ParsedSendUrl; send: AccessedSend; passwordHash?: string }
  | { status: 'downloading' }
  | { status: 'error'; message: string };
```

Preserve the user-gesture permission rule: call `requestOrigin` directly from the Access click path before any unrelated await. Narrow `SendAccessError` with a type guard instead of casting a caught value.

- [ ] **Step 4: Run Receive and core access tests**

```powershell
npm.cmd test -- src\ui\receive\receive-app.test.ts src\core\vault\send-access.test.ts
npm.cmd run typecheck
```

Expected: PASS while `receive.ts` still runs the old UI.

- [ ] **Step 5: Commit**

```powershell
git add src\ui\receive && git commit -m "feat: build Lit Receive flow" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 12: Build Lit Content Surfaces Behind Existing Factories

**Files:**
- Create all `src\content\ui\*.ts` files listed in File Structure
- Create: `src\content\surface-position.ts`
- Test: matching `*.test.ts`
- Do not yet modify active factories in `popover.ts`, `save-bar.ts`, `notice.ts`, or `passkey-consent.ts`

**Interfaces:**
- `mountClosedSurface<T extends HTMLElement>(tagName, configure)` returns host, retained root, element, and remove.
- Components accept callbacks as properties and enforce trusted events internally.
- Positioning is a pure function returning viewport-clamped `{ left, top, placement }`.

- [ ] **Step 1: Write failing positioning and component tests**

Cover:

- popover below, above, and constrained vertical clamp;
- list max height and local scroll class;
- login/card/identity headers and empty states;
- candidate IDs absent from DOM attributes;
- save action/dismiss and inert page-controlled text;
- notice long-word wrap and four-second dismissal;
- passkey confirm/cancel/outside/Escape, at-most-once result;
- registration new/existing/cancel and long target list;
- dark/reduced-motion token presence;
- closed host has `host.shadowRoot === null`.

- [ ] **Step 2: Run and verify failure**

```powershell
npm.cmd test -- src\content\ui src\content\surface-position.test.ts
```

Expected: FAIL because the Lit surface modules do not exist.

- [ ] **Step 3: Implement closed mounting and pure positioning**

```ts
export function mountClosedSurface<T extends HTMLElement>(
  tagName: string,
  configure: (element: T) => void,
): { host: HTMLDivElement; root: ShadowRoot; element: T; remove(): void } {
  const host = document.createElement('div');
  const root = host.attachShadow({ mode: 'closed' });
  const element = document.createElement(tagName) as T;
  configure(element);
  root.append(element);
  (document.body ?? document.documentElement).append(host);
  return { host, root, element, remove: () => host.remove() };
}
```

`surface-position.ts` clamps both axes with 8 px popover margins and 16 px modal margins. It must not read globals so tests can supply dimensions.

- [ ] **Step 4: Implement trusted Lit elements**

Keep callbacks as non-reflected properties. Candidate identity stays in an in-memory array indexed by the rendered row; never emit cipher IDs into data attributes. Render all site strings with `${value}` bindings.

- [ ] **Step 5: Run content component and existing security tests**

```powershell
npm.cmd test -- src\content\ui src\content\surface-position.test.ts src\content\popover.test.ts src\content\save-bar.test.ts src\content\notice.test.ts src\content\passkey-consent.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: new component tests PASS; existing factory tests remain PASS because active files are unchanged.

- [ ] **Step 6: Commit**

```powershell
git add src\content\ui src\content\surface-position.ts src\content\surface-position.test.ts && git commit -m "feat: build Lit content surfaces" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 13: Add Deterministic Playwright Geometry and Visual Tests

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `tsconfig.json`
- Create: `playwright.config.ts`
- Create: `tools\build-ui-fixtures.mjs`
- Create all `test\ui-render\*` files listed in File Structure
- Create: approved screenshot files generated by Playwright

**Interfaces:**
- Query parameters: `surface`, `state`, `theme`, and `count`.
- Fixture entry mounts components with injected deterministic dependencies; it never talks to a real worker.

- [ ] **Step 1: Add scripts and install Chromium**

Add:

```json
"build:ui-fixtures": "node tools/build-ui-fixtures.mjs",
"test:ui": "node tools/build-ui-fixtures.mjs && playwright test",
"test:ui:update": "node tools/build-ui-fixtures.mjs && playwright test --update-snapshots"
```

Add `playwright.config.ts` to `tsconfig.json`'s `include` array.

Run:

```powershell
npx.cmd playwright install chromium
```

Expected: Chromium installs successfully.

- [ ] **Step 2: Write failing fixture and layout tests**

`layout.spec.ts` must assert:

```ts
test('popup has no horizontal overflow at 320px', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 520 });
  await page.goto('/test/ui-render/fixture.html?surface=popup&state=suggestions&count=50');
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});

test('candidate list owns short-viewport scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 404, height: 360 });
  await page.goto('/test/ui-render/fixture.html?surface=popup&state=suggestions&count=50');
  const geometry = await page.locator('[data-scroll-region="suggestions"]').evaluate((element) => ({
    clientHeight: element.clientHeight,
    scrollHeight: element.scrollHeight,
  }));
  expect(geometry.scrollHeight).toBeGreaterThan(geometry.clientHeight);
  expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBeLessThanOrEqual(360);
});
```

Add 320/404/768 widths, short height, light/dark, CSS 200% zoom, long unbroken text, popup auth/list/detail/editor/tools, Options, Receive, popover, save, notice, consent, and registration picker.

- [ ] **Step 3: Run and verify fixture failure**

```powershell
npm.cmd run test:ui
```

Expected: FAIL because fixture build/server/config are missing.

- [ ] **Step 4: Implement fixture build and server**

`tools\build-ui-fixtures.mjs` bundles `test\ui-render\fixture-entry.ts` to `dist\ui-test\fixture.js` with esbuild, ESM, ES2022, and no splitting:

```js
import * as esbuild from 'esbuild';
import { mkdir } from 'node:fs/promises';

await mkdir('dist/ui-test', { recursive: true });
await esbuild.build({
  entryPoints: ['test/ui-render/fixture-entry.ts'],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  outfile: 'dist/ui-test/fixture.js',
  sourcemap: true,
});
```

`server.mjs` serves only repository files from `127.0.0.1:4173` and rejects path traversal:

```js
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';

const root = resolve('.');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png' };
createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url ?? '/', 'http://127.0.0.1').pathname);
    const file = resolve(root, `.${pathname}`);
    if (file !== root && !file.startsWith(`${root}${sep}`)) {
      response.writeHead(403).end();
      return;
    }
    const body = await readFile(file);
    response.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' });
    response.end(body);
  } catch {
    response.writeHead(404).end();
  }
}).listen(4173, '127.0.0.1');
```

Configure Playwright:

```ts
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'test/ui-render',
  testMatch: '**/*.spec.ts',
  use: { baseURL: 'http://127.0.0.1:4173', colorScheme: 'light' },
  webServer: {
    command: 'node test/ui-render/server.mjs',
    port: 4173,
    reuseExistingServer: !process.env.CI,
  },
});
```

- [ ] **Step 5: Add keyboard and screenshot coverage**

Test tabs, menus, dialogs, focus restoration, Escape, and live statuses. In `accessibility.spec.ts`, compute WCAG relative luminance from `getComputedStyle` and require at least 4.5:1 for normal text selectors in both themes. Keep one screenshot for each approved family/state rather than every permutation.

Generate baselines:

```powershell
npm.cmd run test:ui:update
npm.cmd run test:ui
```

Expected: PASS and stable PNG baselines are created under `test\ui-render`.

- [ ] **Step 6: Commit**

```powershell
git add package.json package-lock.json playwright.config.ts tools\build-ui-fixtures.mjs test\ui-render && git commit -m "test: add rendered UI regression coverage" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 14: Perform the Atomic UI Cutover

**Files:**
- Replace: `src\ui\popup\popup.ts`
- Replace: `src\ui\options\options.ts`
- Replace: `src\ui\receive\receive.ts`
- Modify: `src\ui\popup\popup.html`
- Modify: `src\ui\options\options.html`
- Modify: `src\ui\receive\receive.html`
- Replace with minimal document CSS: `src\ui\popup\popup.css`, `src\ui\options\options.css`, `src\ui\receive\receive.css`
- Delete after removing references: `src\ui\theme.css`, `src\ui\icons.ts`
- Modify active content factories: `src\content\popover.ts`, `save-bar.ts`, `notice.ts`, `passkey-consent.ts`
- Modify: `src\content\autofill.ts`
- Modify existing content tests to assert the Lit-backed factories
- Modify: `build.mjs`
- Create: `tools\assert-build.mjs`
- Modify: `README.md`
- Modify: `docs\tech-debt.md`

**Interfaces:**
- Production entry files become thin dependency adapters and mounts.
- Existing content factory function names and callback contracts remain stable for their current callers.
- Build output paths remain unchanged.

- [ ] **Step 1: Write failing atomic-cutover assertions**

Create `tools\assert-build.mjs` to fail unless:

- all three HTML files load only their own script and minimal page CSS;
- `dist\ui\popup\popup.js`, Options, Receive, and content bundles exist;
- built HTML has no `theme.css` reference;
- manifest includes `activeTab` and `webNavigation`;
- production source entry files contain no `innerHTML =` renderer;
- `dist` contains no old `theme.css`.

Use this assertion shape:

```js
import { access, readFile } from 'node:fs/promises';

const required = [
  'dist/manifest.json',
  'dist/ui/popup/popup.html',
  'dist/ui/popup/popup.js',
  'dist/ui/options/options.js',
  'dist/ui/receive/receive.js',
  'dist/content/autofill.js',
];
await Promise.all(required.map((file) => access(file)));

for (const page of ['popup', 'options', 'receive']) {
  const html = await readFile(`dist/ui/${page}/${page}.html`, 'utf8');
  if (html.includes('theme.css')) throw new Error(`${page}.html still references theme.css`);
  const source = await readFile(`src/ui/${page}/${page}.ts`, 'utf8');
  if (/\binnerHTML\s*=/.test(source)) throw new Error(`${page}.ts still contains an imperative renderer`);
}

const manifest = JSON.parse(await readFile('dist/manifest.json', 'utf8'));
for (const permission of ['activeTab', 'webNavigation']) {
  if (!manifest.permissions?.includes(permission)) throw new Error(`Missing ${permission} permission`);
}

try {
  await access('dist/ui/theme.css');
  throw new Error('Legacy dist/ui/theme.css still exists');
} catch (error) {
  if (error instanceof Error && error.message.startsWith('Legacy')) throw error;
}
```

Add/update manifest and content factory tests for new mounts.

- [ ] **Step 2: Run assertions and verify failure against the old active UI**

```powershell
npm.cmd run build:prod
node tools\assert-build.mjs
```

Expected: FAIL on legacy theme/renderer assertions.

- [ ] **Step 3: Replace all entry points in one change**

Use thin mounts:

```ts
// src/ui/popup/popup.ts
import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';
import { VwPopupApp } from './app.js';

const app = document.createElement('vw-popup-app') as VwPopupApp;
app.request = sendRequest;
app.browser = {
  getActiveTabId: async () => (await browser.tabs.query({ active: true, currentWindow: true }))[0]?.id,
  openOptions: () => browser.runtime.openOptionsPage(),
  openReceive: async () => {
    await browser.tabs.create({ url: browser.runtime.getURL('ui/receive/receive.html') });
  },
};
document.getElementById('app')?.append(app);
```

Options and Receive use the same pattern with their approved dependency interfaces. Replace current content factories with `mountClosedSurface` plus the new elements, preserving current exports. Register frame inspection and commit messages in `autofill.ts` and return their typed responses from the runtime listener.

- [ ] **Step 4: Remove legacy UI code and static assets**

Delete the imperative bodies, old icon-string helper, and old theme. Keep only minimal document CSS and change `build.mjs` to copy the new static set. Do not enable esbuild splitting for content scripts.

Change the production script to run the assertion automatically:

```json
"build:prod": "node build.mjs --prod && node tools/assert-build.mjs"
```

Update README:

- Lit 3 component system;
- 404 px context-first popup;
- Suggestions and direct Fill;
- settings rail;
- `npm.cmd run test:ui`.

Update `docs\tech-debt.md` with the delivered UI rewrite and any real-browser residuals discovered during verification.

- [ ] **Step 5: Run all automated gates**

```powershell
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build:prod
node tools\assert-build.mjs
npm.cmd run test:ui
```

Expected: all commands PASS.

- [ ] **Step 6: Run the real Chrome/Vaultwarden smoke**

Use the repository test environment and verify:

1. login, code-based 2FA, remembered device, unlock, PIN, lock, logout;
2. sync, Suggestions, All items, search, folders, collections, trash;
3. top-frame Fill and nested-iframe Fill;
4. navigate between inspection and Fill and confirm `target_changed`;
5. reprompt refusal and extension-side verification;
6. all detail/editor/attachment actions;
7. generator, health/HIBP, Sends, account security, accounts;
8. Options permission save, security settings, Data import/export;
9. Receive text and file;
10. autofill popover, save bar, notice, passkey consent and registration;
11. 320/404 widths, short viewport, dark mode, keyboard-only use, and 200% zoom.

Expected: no unexplained overflow, inaccessible action, console error, secret in popup state, or security-boundary regression.

- [ ] **Step 7: Commit the atomic cutover**

```powershell
git add build.mjs package.json package-lock.json README.md docs\tech-debt.md tools\assert-build.mjs src\ui src\content src\manifest.json src\manifest.test.ts test\ui-render playwright.config.ts && git commit -m "feat: atomically switch to Lit UI" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Completion Gate

The implementation is complete only when:

- Tasks 1-13 are present but no old/new mixed UI has been integrated;
- Task 14 switches every surface together;
- no legacy imperative renderer remains active;
- credentials are absent from popup suggestion/fill state;
- all automated commands and the real Chrome/Vaultwarden smoke pass;
- the final diff receives a code review through the requesting-code-review skill;
- branch completion uses the finishing-a-development-branch skill.
