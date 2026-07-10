# 1Password-Aligned Extension UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert every extension surface to the approved high-contrast, blue-led visual system and make the unlocked popup a 600 x 450 double-pane credential workspace with a 350 x 450 single-pane fallback.

**Architecture:** Preserve the current Lit components, root-owned requests, typed routes, and security boundaries. Add a geometry-only popup frame, separate the retained vault scope from the active right-pane route in `VwPopupApp`, and restyle existing feature components through revised shared tokens and controls. Full-page and embedded surfaces consume the same semantic tokens without inheriting popup layout.

**Tech Stack:** TypeScript 6, Lit 3.3, MV3, Vitest 4 with happy-dom, Playwright 1.61 with Chromium, esbuild.

## Global Constraints

- Keep `lit@^3.3.3` as the only UI framework.
- Use only local system fonts: `Segoe UI Variable Text`, `Segoe UI Variable`, `Segoe UI`, `system-ui`, and `sans-serif`; machine values use `Cascadia Code`, `Consolas`, `ui-monospace`, and `monospace`.
- Do not add or copy 1Password code, compiled modules, font files, icons, images, logos, screenshots, product copy, or other proprietary assets.
- The unlocked popup defaults to 600 x 450 CSS px with a 260 px list pane and 340 px detail/workflow pane.
- Authentication and constrained layouts use a 350 x 450 CSS px single-pane mode capped at `100vw`.
- Use the approved 14 px body, 12 px metadata, and 20 px item-title scale; letter spacing remains zero.
- Use 4, 8, and 12 px radii and 4, 8, 12, 16, 24, and 32 px spacing increments.
- Blue carries primary action, selection, link, and focus semantics; success, warning, and danger retain distinct colors.
- Keep all root-owned worker requests, typed outcomes, reprompt enforcement, credential routing, closed Shadow DOM, and `Event.isTrusted` boundaries unchanged.
- Never place credentials in popup route data, list props, events, DOM attributes, logs, fixture snapshots, or Fill responses.
- Every changed behavior follows TDD: write a focused test, observe the expected failure, implement the minimum behavior, then rerun focused and related tests.
- Preserve light/dark mode, keyboard operation, reduced motion, 320 px containment, short-viewport reachability, and 200% zoom support.

## File Structure

- `src/ui/components/tokens.ts`, `styles.ts`: shared semantic visual contract.
- `src/ui/popup/popup-frame.ts`: new 600/350 px geometry-only frame.
- `src/ui/popup/types.ts`, `app.ts`: layout mode, retained vault scope, selected item, and pane orchestration.
- Existing popup feature components: compact selectable list and right-pane workflows.
- `src/ui/components/page-shell.ts`, Options, and Receive files: full-page workbench treatment.
- Existing `src/content/ui/*.ts`: isolated embedded variant.
- `test/ui-render/*`: deterministic geometry, keyboard, contrast, and screenshot verification.

---

### Task 1: Replace Shared Visual Tokens and Controls

**Files:**
- Modify: `src/ui/components/tokens.ts`
- Modify: `src/ui/components/styles.ts`
- Modify: `src/ui/components/tokens.test.ts`

**Interfaces:**
- Produces: `themeTokens` with popup geometry, semantic color/type/space/radius/duration properties.
- Produces: `controlStyles` classes `.button`, `.icon-button`, `.field`, `.input`, `.select`, `.field-group`, `.field-row`, and `.mono`.

- [ ] **Step 1: Write failing token tests**

Add to `tokens.test.ts`:

```ts
it('pins the approved geometry and compact visual contract', () => {
  const css = themeTokens.cssText;
  expect(css).toContain('--vw-popup-double-width:600px');
  expect(css).toContain('--vw-popup-single-width:350px');
  expect(css).toContain('--vw-popup-height:450px');
  expect(css).toContain('--vw-blue:hsl(212 96% 47%)');
  expect(css).toContain('--vw-font-size-body:14px');
  expect(css).toContain('--vw-font-size-meta:12px');
  expect(css).toContain('--vw-radius-row:8px');
  expect(css).toContain('--vw-duration-normal:175ms');
});

it('defines dark equivalents and reduced motion', () => {
  const css = themeTokens.cssText;
  expect(css).toContain('prefers-color-scheme:dark');
  expect(css).toContain('--vw-row-selected:hsl(214 100% 16%)');
  expect(css).toContain('--vw-duration-normal:0ms');
});
```

- [ ] **Step 2: Verify the expected failure**

```powershell
npm.cmd test -- src\ui\components\tokens.test.ts
```

Expected: FAIL because the current tokens still describe the 404 px system.

- [ ] **Step 3: Implement the token property set**

Define these exact light properties and dark semantic equivalents in `themeTokens`:

```css
--vw-popup-double-width:600px; --vw-popup-single-width:350px;
--vw-popup-height:450px; --vw-pane-list-width:260px; --vw-pane-detail-width:340px;
--vw-ink-strong:#090a0c; --vw-ink:rgb(0 0 0 / 82%);
--vw-muted:rgb(0 0 0 / 62%); --vw-disabled:rgb(0 0 0 / 36%);
--vw-panel:#fff; --vw-canvas:#fafafa; --vw-blue:hsl(212 96% 47%);
--vw-blue-hover:hsl(216 100% 39%); --vw-blue-pressed:hsl(224 100% 33%);
--vw-blue-text:hsl(212 100% 35%); --vw-blue-weak:hsl(214 100% 96%);
--vw-row-selected:hsl(215 100% 94%); --vw-line:rgb(0 0 0 / 13%);
--vw-line-weak:rgb(0 0 0 / 7%); --vw-radius-small:4px;
--vw-radius-row:8px; --vw-radius-large:12px; --vw-font-size-title:20px;
--vw-font-size-view:16px; --vw-font-size-body:14px; --vw-font-size-meta:12px;
--vw-duration-fast:75ms; --vw-duration-normal:175ms;
```

Dark mode uses 89% white primary text, 78.5% secondary text, `hsl(214 100% 16%)` selected rows, and lighter blue text/focus. Reduced motion sets both durations to `0ms`. Update `controlStyles` to 34-36 px controls, 8 px radii, a 2 px focus ring, and outer-border/internal-divider field groups.

- [ ] **Step 4: Verify the foundation**

```powershell
npm.cmd test -- src\ui\components\tokens.test.ts src\ui\components\icon.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src\ui\components\tokens.ts src\ui\components\styles.ts src\ui\components\tokens.test.ts
git commit -m "feat(ui): align shared visual tokens"
```

---

### Task 2: Add the Responsive Popup Frame

**Files:**
- Create: `src/ui/popup/popup-frame.ts`
- Create: `src/ui/popup/popup-frame.test.ts`
- Modify: `src/ui/popup/types.ts`
- Modify: `src/ui/popup/popup.css`

**Interfaces:**
- Produces: `PopupLayoutMode = 'double' | 'single' | 'auth'`.
- Produces: `<vw-popup-frame>` with `toolbar`, `list`, and `detail` slots plus a default single-pane slot.
- Produces: `data-popup-frame`, `data-list-pane`, and `data-detail-pane` hooks.

- [ ] **Step 1: Write failing frame tests**

Create `popup-frame.test.ts`:

```ts
// @vitest-environment happy-dom
import { afterEach, expect, it } from 'vitest';
import './popup-frame.js';
import type { VwPopupFrame } from './popup-frame.js';

async function mount(mode: 'double' | 'single' | 'auth'): Promise<VwPopupFrame> {
  const frame = document.createElement('vw-popup-frame') as VwPopupFrame;
  frame.mode = mode;
  frame.innerHTML = '<div slot="toolbar">t</div><div slot="list">l</div><div slot="detail">d</div><div>s</div>';
  document.body.append(frame);
  await frame.updateComplete;
  return frame;
}

afterEach(() => document.body.replaceChildren());

it('renders two panes in double mode', async () => {
  const frame = await mount('double');
  expect(frame.shadowRoot?.querySelector('[data-list-pane]')).not.toBeNull();
  expect(frame.shadowRoot?.querySelector('[data-detail-pane]')).not.toBeNull();
});

it.each(['single', 'auth'] as const)('renders one region in %s mode', async (mode) => {
  const frame = await mount(mode);
  expect(frame.shadowRoot?.querySelector('[data-single-pane]')).not.toBeNull();
  expect(frame.shadowRoot?.querySelector('[data-list-pane]')).toBeNull();
});
```

- [ ] **Step 2: Verify missing-element failure**

```powershell
npm.cmd test -- src\ui\popup\popup-frame.test.ts
```

Expected: FAIL because `popup-frame.ts` does not exist.

- [ ] **Step 3: Implement the geometry-only component**

Use:

```ts
export type PopupLayoutMode = 'double' | 'single' | 'auth';

export class VwPopupFrame extends LitElement {
  static override properties = { mode: { type: String, reflect: true } };
  declare mode: PopupLayoutMode;
  constructor() { super(); this.mode = 'double'; }
  protected override render() {
    if (this.mode !== 'double') {
      return html`<section data-popup-frame data-single-pane><slot></slot></section>`;
    }
    return html`<section data-popup-frame class="frame">
      <header><slot name="toolbar"></slot></header>
      <div class="workspace">
        <aside data-list-pane><slot name="list"></slot></aside>
        <main data-detail-pane><slot name="detail"></slot></main>
      </div>
    </section>`;
  }
}
```

Double mode is `min(600px, 100vw)` by `min(450px, 100vh)` with a fixed 52 px toolbar and `260px minmax(0, 340px)` tracks. Single/auth is `min(350px, 100vw)`. Both panes use `min-height:0; overflow:auto`; the document uses `overflow:hidden`. At `max-width:480px`, render only single content rather than squeezing both panes.

- [ ] **Step 4: Verify frame and existing popup tests**

```powershell
npm.cmd test -- src\ui\popup\popup-frame.test.ts src\ui\popup\app.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src\ui\popup\popup-frame.ts src\ui\popup\popup-frame.test.ts src\ui\popup\types.ts src\ui\popup\popup.css
git commit -m "feat(popup): add responsive two-pane frame"
```

---

### Task 3: Make Credential Rows Selectable and Keyboard Navigable

**Files:**
- Modify: `src/ui/popup/vault/vault-item-row.ts`
- Modify: `src/ui/popup/vault/vault-item-row.test.ts`
- Modify: `src/ui/popup/vault/suggestions-view.ts`
- Modify: `src/ui/popup/vault/suggestions-view.test.ts`
- Modify: `src/ui/popup/vault/all-items-view.ts`
- Modify: `src/ui/popup/vault/all-items-view.test.ts`
- Modify: `src/ui/popup/vault/vault-view.ts`
- Modify: `src/ui/popup/vault/vault-view.test.ts`

**Interfaces:**
- Produces: non-reflected `selectedCipherId: string | null` and row `selected: boolean` properties.
- Produces: boolean `data-selected`; raw cipher IDs remain absent from DOM attributes.
- Preserves: `vw-item-open` and `vw-suggestion-fill` event details.

- [ ] **Step 1: Add failing selected-row and keyboard tests**

Extend `vault-item-row.test.ts`:

```ts
it('exposes selected semantics without reflecting the cipher id', async () => {
  const el = await mount(summary({ id: 'secret-id' }));
  el.selected = true;
  await el.updateComplete;
  const button = el.shadowRoot!.querySelector('button')!;
  expect(button.getAttribute('aria-selected')).toBe('true');
  expect(button.hasAttribute('data-selected')).toBe(true);
  expect(el.shadowRoot!.innerHTML).not.toContain('secret-id');
});

it('opens the row on Enter', async () => {
  const el = await mount(summary({ id: 'abc' }));
  const opened = vi.fn();
  el.addEventListener('vw-item-open', opened);
  el.shadowRoot!.querySelector('button')!.dispatchEvent(
    new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }),
  );
  expect(opened).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'abc' } }));
});
```

Add tests that `vault-view` passes selection to the matching row and that ArrowDown, ArrowUp, Home, and End move focus without changing selection until Enter.

- [ ] **Step 2: Verify the new tests fail**

```powershell
npm.cmd test -- src\ui\popup\vault\vault-item-row.test.ts src\ui\popup\vault\suggestions-view.test.ts src\ui\popup\vault\all-items-view.test.ts src\ui\popup\vault\vault-view.test.ts
```

Expected: FAIL because rows have no selection or list keyboard navigation.

- [ ] **Step 3: Implement compact selectable rows**

Add:

```ts
static override properties = {
  item: { attribute: false },
  selected: { type: Boolean },
};
declare selected: boolean;
```

Render the button with `role="option"`, `aria-selected`, boolean `data-selected`, click, and Enter handlers. Use stable 52-54 px row geometry, a fixed 36 px glyph column, 14 px title, 12 px subtitle, blue selection with inverse text, weak-blue hover, and an independent focus outline. Apply the same contract to Suggestions without rendering target or cipher IDs.

- [ ] **Step 4: Verify list and DOM-security tests**

```powershell
npm.cmd test -- src\ui\popup\vault src\ui\popup\utils.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src\ui\popup\vault
git commit -m "feat(popup): add selectable credential lists"
```

---

### Task 4: Integrate Persistent Double-Pane Navigation

**Files:**
- Modify: `src/ui/popup/app.ts`
- Modify: `src/ui/popup/app.test.ts`
- Modify: `src/ui/popup/types.ts`
- Modify: `src/ui/popup/vault/popup-header.ts`
- Modify: `src/ui/popup/vault/popup-header.test.ts`
- Modify: `src/ui/popup/popup.ts`

**Interfaces:**
- Consumes: `<vw-popup-frame>` and existing root request/browser seams.
- Produces: root state `vaultScope: 'suggestions' | 'all'` and `selectedCipherId: string | null`.
- Produces: `layoutMode(): PopupLayoutMode` and `renderUnlockedWorkspace(route)`.
- Preserves: request methods, reprompt handling, Fill routing, clipboard behavior, and account cleanup.

- [ ] **Step 1: Write failing root integration tests**

Add to `app.test.ts`:

```ts
it('renders the unlocked vault in a double-pane frame', async () => {
  const app = await mountVault(unlockedHandlers(), browserSeam());
  const frame = app.shadowRoot!.querySelector('vw-popup-frame');
  expect(frame?.getAttribute('mode')).toBe('double');
  expect(frame?.querySelector('[slot="list"] vw-vault-view')).not.toBeNull();
});

it('keeps the list mounted while detail opens in the right pane', async () => {
  const app = await mountVault(unlockedHandlers(), browserSeam());
  const list = app.shadowRoot!.querySelector('vw-vault-view');
  await openDetail(app, 'c1');
  expect(app.shadowRoot!.querySelector('vw-vault-view')).toBe(list);
  expect(app.shadowRoot!.querySelector('[slot="detail"] vw-item-detail')).not.toBeNull();
  expect(app.selectedCipherId).toBe('c1');
});

it('uses auth mode for logged-out routes', async () => {
  const app = await mountApp(fakeRequest({
    'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
  }));
  expect(app.shadowRoot!.querySelector('vw-popup-frame')?.getAttribute('mode')).toBe('auth');
});
```

Add one test each proving lock, logout, and account switch clear `selectedCipherId` and secret detail state.

- [ ] **Step 2: Verify frame and persistence failures**

```powershell
npm.cmd test -- src\ui\popup\app.test.ts src\ui\popup\vault\popup-header.test.ts
```

Expected: FAIL because routes still replace the complete popup.

- [ ] **Step 3: Separate list scope from right-pane route**

Add root properties and defaults:

```ts
declare vaultScope: 'suggestions' | 'all';
declare selectedCipherId: string | null;

this.vaultScope = 'suggestions';
this.selectedCipherId = null;
```

`enterVault()` sets Suggestions and starts existing reads. Tab changes update `vaultScope`. Navigating to detail sets selection and loads detail without unmounting the list. `resetVaultState()`, lock, logout, and account switch set selection to `null` and clear all current secret state. Neither property may contain passwords or decrypted detail values.

- [ ] **Step 4: Compose unlocked routes in the frame**

Implement:

```ts
private layoutMode(): PopupLayoutMode {
  const name = this.route.name;
  return name === 'login' || name === 'register' || name === 'twoFactor' || name === 'unlock'
    ? 'auth'
    : 'double';
}

private renderUnlockedWorkspace(route: UnlockedPopupRoute) {
  return html`<vw-popup-frame mode="double">
    <vw-popup-header slot="toolbar" ...></vw-popup-header>
    <vw-vault-view slot="list"
      .scope=${this.vaultScope}
      .selectedCipherId=${this.selectedCipherId}
      ...></vw-vault-view>
    <section slot="detail" class="detail-route">${this.renderRightPane(route)}</section>
  </vw-popup-frame>`;
}
```

`renderRightPane` reuses existing detail, editor, generator, health, Sends, PIN, account security, trash, loading, and error renderers. Single mode renders one active route with Back and focus return; it does not duplicate secret state.

Update `popup-header.ts` to render account context, search, and one `New item` text command. Search dispatches `{ query }` and switches to All items for non-empty input. Generator remains reachable from tools.

- [ ] **Step 5: Verify popup and autofill security regressions**

```powershell
npm.cmd test -- src\ui\popup src\background\tab-autofill.test.ts src\content\frame-autofill.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS, including reprompt, clipboard, Fill outcome, and cleanup tests.

- [ ] **Step 6: Commit**

```powershell
git add src\ui\popup
git commit -m "feat(popup): keep vault context in a two-pane workspace"
```

---

### Task 5: Align Detail, Editor, Tools, Menus, and Auth

**Files:**
- Modify: `src/ui/popup/item/item-detail.ts`, `item-detail.test.ts`, `reprompt-gate.ts`
- Modify: `src/ui/popup/editor/type-picker.ts`, `cipher-editor.ts`, `cipher-editor.test.ts`
- Modify: all `src/ui/popup/tools/*-view.ts` files and focused tests
- Modify: `src/ui/popup/menus/account-menu.ts`, `tools-menu.ts` and tests
- Modify: `src/ui/popup/auth/auth-views.ts`, `auth-views.test.ts`

**Interfaces:**
- Consumes: Task 4 right-pane slot and Task 1 controls.
- Produces: `.view-toolbar`, `.view-scroll`, `.field-group`, and `.view-actions` structural hooks.
- Preserves: every existing component event name and detail type.

- [ ] **Step 1: Add failing semantic-structure tests**

Add focused assertions:

```ts
it('groups related detail values in field groups', async () => {
  const el = await mountDetail(loginSummary(), loginCipher());
  expect(el.shadowRoot!.querySelectorAll('[data-field-group]').length).toBeGreaterThan(0);
  expect(el.shadowRoot!.querySelector('[data-detail-scroll]')).not.toBeNull();
});

it('keeps editor actions in a reachable action row', async () => {
  const editor = await mountEditor(loginContext());
  expect(editor.shadowRoot!.querySelector('[data-view-scroll]')).not.toBeNull();
  expect(editor.shadowRoot!.querySelector('[data-view-actions]')).not.toBeNull();
});
```

Add equivalent structure assertions to generator, health, Sends, account security, PIN, reprompt, and auth tests. Menu tests continue asserting keyboard navigation and focus restoration.

- [ ] **Step 2: Verify structure tests fail**

```powershell
npm.cmd test -- src\ui\popup\item src\ui\popup\editor src\ui\popup\tools src\ui\popup\menus src\ui\popup\auth
```

Expected: FAIL only on the new hooks.

- [ ] **Step 3: Implement right-pane visual structure**

For every right-pane feature:

- use one `data-view-scroll` region with `min-height:0; overflow:auto`;
- use 20 px item title, 14 px values, and 12 px labels;
- replace nested cards with one outer `.field-group` and internal dividers;
- keep password, TOTP, URL, and recovery values in `.mono` where appropriate;
- expose only one primary action and separate structural/destructive actions;
- preserve all request and event code;
- set every SVG to an explicit 16, 18, 20, or 24 px role size.

Auth stays centered in the 350 px frame with no empty list pane or decorative hero.

- [ ] **Step 4: Verify all popup components**

```powershell
npm.cmd test -- src\ui\popup
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src\ui\popup
git commit -m "feat(popup): align credential workflows with the new UI"
```

---

### Task 6: Rebuild Options and Receive Workbenches

**Files:**
- Modify: `src/ui/components/page-shell.ts`, `page-shell.test.ts`
- Modify: `src/ui/options/options-app.ts`, `options-app.test.ts`
- Modify: all `src/ui/options/sections/*.ts` and focused tests
- Modify: `src/ui/options/options.css`
- Modify: `src/ui/receive/receive-app.ts`, `receive-app.test.ts`, `receive.css`, `receive.html`

**Interfaces:**
- Produces: `data-page-shell`, `data-settings-rail`, `data-settings-content`, and `data-setting-row` hooks.
- Preserves: `vw-tab-change`, all Options save/import/export events, and Receive dependency/state contracts.

- [ ] **Step 1: Write failing workbench tests**

Add:

```ts
it('renders a bounded settings rail and content workspace', async () => {
  const shell = await mountWideShell();
  expect(shell.shadowRoot!.querySelector('[data-settings-rail]')).not.toBeNull();
  expect(shell.shadowRoot!.querySelector('[data-settings-content]')).not.toBeNull();
  for (const icon of shell.shadowRoot!.querySelectorAll('nav svg')) {
    expect(getComputedStyle(icon).width).toBe('18px');
    expect(getComputedStyle(icon).height).toBe('18px');
  }
});

it('renders connection settings as workbench rows', async () => {
  const section = await mountConnection();
  expect(section.shadowRoot!.querySelector('[data-setting-row]')).not.toBeNull();
  expect(section.shadowRoot!.querySelector('[data-primary-action]')?.textContent).toContain('Save connection');
});
```

Add a Receive assertion for one page heading, one constrained task column, and field-group output states.

- [ ] **Step 2: Verify full-page failures**

```powershell
npm.cmd test -- src\ui\components\page-shell.test.ts src\ui\options src\ui\receive
```

Expected: FAIL because current forms lack workbench rows and rail icons are uncontrolled.

- [ ] **Step 3: Implement full-page layouts**

`page-shell.ts` uses a white 206 px rail, 1 px divider, 18 x 18 icons, 39 px navigation rows, and a solid-blue selected row with white text. `main` uses `min-width:0` and no overlap. Narrow mode retains the native selector.

Each section renders this structure:

```ts
<header class="section-heading">
  <h1>Connection</h1>
  <p>Choose the Vaultwarden or Bitwarden server used by this browser.</p>
</header>
<section class="settings-group">
  <h2>Server connection</h2>
  <div data-setting-row class="setting-row">...</div>
</section>
```

Buttons use `white-space:nowrap` and stable minimum width. Receive uses the same heading and field groups without a rail, while retaining its exact state machine and permission-first await order.

- [ ] **Step 4: Verify full-page and protocol tests**

```powershell
npm.cmd test -- src\ui\components\page-shell.test.ts src\ui\options src\ui\receive src\background\settings.test.ts src\core\vault\vault-io.test.ts src\core\vault\send-access.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS, including permission-request tests.

- [ ] **Step 5: Commit**

```powershell
git add src\ui\components\page-shell.ts src\ui\components\page-shell.test.ts src\ui\options src\ui\receive
git commit -m "feat(ui): rebuild settings and receive workbenches"
```

---

### Task 7: Align Embedded Surfaces Without Weakening Isolation

**Files:**
- Modify: `src/content/ui/autofill-popover-element.ts`, `autofill-popover-element.test.ts`
- Modify: `src/content/ui/save-bar-element.ts`, `save-bar-element.test.ts`
- Modify: `src/content/ui/notice-element.ts`, `notice-element.test.ts`
- Modify: `src/content/ui/passkey-dialog-element.ts`, `passkey-dialog-element.test.ts`

**Interfaces:**
- Consumes: approved semantic values as component-local custom properties.
- Preserves: callback properties, candidate indexing, trusted-event checks, at-most-once results, and closed-root mounting.

- [ ] **Step 1: Add failing visual-contract security tests**

```ts
it('uses selected-row semantics without exposing candidate ids', async () => {
  const popover = await mountPopover();
  const row = popover.shadowRoot!.querySelector('[role="option"]')!;
  expect(row.getAttribute('aria-selected')).toBe('true');
  expect(popover.shadowRoot!.innerHTML).not.toContain('cipher-secret-id');
});

it('keeps trusted callbacks as properties', async () => {
  const consent = await mountConsent();
  expect(consent.getAttributeNames()).not.toContain('onresult');
});
```

- [ ] **Step 2: Verify new tests fail while existing security tests pass**

```powershell
npm.cmd test -- src\content\ui src\content\popover.test.ts src\content\save-bar.test.ts src\content\notice.test.ts src\content\passkey-consent.test.ts
```

Expected: FAIL on selected-row semantics only.

- [ ] **Step 3: Apply the embedded visual variant**

Use 14/12 px type, 8 px row/control geometry, blue selection and primary actions, and neutral borders. Autofill rows are 48-50 px. Save and notice remain horizontal bars. Passkey dialogs use one 12 px modal radius and one primary command.

Do not change `mountClosedSurface`, callback types, trusted-click guards, candidate indexing, viewport positioning, or privileged-operation decisions.

- [ ] **Step 4: Verify embedded and security tests**

```powershell
npm.cmd test -- src\content\ui src\content\surface-position.test.ts src\content\popover.test.ts src\content\save-bar.test.ts src\content\notice.test.ts src\content\passkey-consent.test.ts
npm.cmd run typecheck
npm.cmd run lint
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add src\content\ui
git commit -m "feat(ui): align embedded browser surfaces"
```

---

### Task 8: Replace Rendered Fixtures and Complete Verification

**Files:**
- Modify: `test/ui-render/fixture-entry.ts`, `helpers.ts`
- Modify: `test/ui-render/layout.spec.ts`, `keyboard.spec.ts`, `accessibility.spec.ts`, `visual.spec.ts`
- Replace: representative files under `test/ui-render/visual.spec.ts-snapshots/`
- Modify: `README.md`
- Modify: `docs/tech-debt.md`

**Interfaces:**
- Extends `FixtureParams` with `layout?: 'double' | 'single'`.
- Produces deterministic double- and single-pane fixture states.
- Provides final evidence for every acceptance criterion.

- [ ] **Step 1: Write failing double/single geometry tests**

Add:

```ts
test('unlocked popup uses a 600 by 450 double-pane frame', async ({ page }) => {
  await page.setViewportSize({ width: 600, height: 450 });
  await gotoFixture(page, { surface: 'popup', state: 'detail', layout: 'double' });
  const frame = page.locator('[data-popup-frame]');
  await expect(frame).toHaveCSS('width', '600px');
  await expect(frame).toHaveCSS('height', '450px');
  await expect(page.locator('[data-list-pane]')).toHaveCSS('width', '260px');
  await expect(page.locator('[data-detail-pane]')).toHaveCSS('width', '340px');
});

test('auth uses a 350 by 450 single-pane frame', async ({ page }) => {
  await page.setViewportSize({ width: 350, height: 450 });
  await gotoFixture(page, { surface: 'popup', state: 'auth', layout: 'single' });
  const frame = page.locator('[data-popup-frame]');
  await expect(frame).toHaveCSS('width', '350px');
  await expect(frame).toHaveCSS('height', '450px');
  await expect(page.locator('[data-detail-pane]')).toHaveCount(0);
});

test('list and detail own scrolling independently', async ({ page }) => {
  await page.setViewportSize({ width: 600, height: 450 });
  await gotoFixture(page, { surface: 'popup', state: 'detail', layout: 'double', count: 50 });
  for (const selector of ['[data-list-pane]', '[data-detail-pane]']) {
    const size = await page.locator(selector).evaluate((element) => ({
      clientHeight: element.clientHeight,
      scrollHeight: element.scrollHeight,
    }));
    expect(size.scrollHeight).toBeGreaterThan(size.clientHeight);
  }
  expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBeLessThanOrEqual(450);
});
```

Add keyboard tests for ArrowDown/Enter selection, right-pane update, Escape/Back in single mode, and focus visibility. Retain 320 px, dark, long-text, short-height, and 200% zoom cases.

- [ ] **Step 2: Verify old fixture failures**

```powershell
npm.cmd run test:ui
```

Expected: FAIL because fixtures still hard-code a 404 px single-column shell.

- [ ] **Step 3: Rebuild fixtures from production components**

Add `layout` to `FixtureParams` and query parsing. Mount `VwPopupFrame` with real header, vault view, and right-pane components. Remove all `width:min(404px,100vw)` fixture CSS. Keep deterministic IDs only in in-memory props.

Use this representative visual matrix:

```ts
const CASES: VisualCase[] = [
  { name: 'popup-double-suggestions-light', params: { surface: 'popup', state: 'suggestions', layout: 'double', count: 8 }, selector: '[data-popup-frame]', viewport: { width: 600, height: 450 } },
  { name: 'popup-double-detail-light', params: { surface: 'popup', state: 'detail', layout: 'double', count: 8 }, selector: '[data-popup-frame]', viewport: { width: 600, height: 450 } },
  { name: 'popup-double-detail-dark', params: { surface: 'popup', state: 'detail', layout: 'double', theme: 'dark', count: 8 }, selector: '[data-popup-frame]', viewport: { width: 600, height: 450 } },
  { name: 'popup-single-auth', params: { surface: 'popup', state: 'auth', layout: 'single' }, selector: '[data-popup-frame]', viewport: { width: 350, height: 450 } },
  { name: 'popup-single-detail', params: { surface: 'popup', state: 'detail', layout: 'single' }, selector: '[data-popup-frame]', viewport: { width: 350, height: 450 } },
  { name: 'options', params: { surface: 'options' }, selector: '#vw-surface', viewport: { width: 1000, height: 700 } },
  { name: 'receive', params: { surface: 'receive' }, selector: '#vw-surface', viewport: { width: 720, height: 600 } },
  { name: 'popover', params: { surface: 'popover' }, selector: 'vw-autofill-popover .box', viewport: { width: 420, height: 420 } },
];
```

- [ ] **Step 4: Generate, inspect, and rerun baselines**

```powershell
npm.cmd run test:ui:update
npm.cmd run test:ui
```

Expected: PASS. Inspect every PNG for overlap, clipping, blank content, uncontrolled icons, unreadable selection, and inconsistent panes. Fix production CSS and regenerate until clean.

- [ ] **Step 5: Update documentation**

Document the 600 x 450 workspace, 350 x 450 auth/constrained flow, retained list context, and `npm.cmd run test:ui` in `README.md`. Add only real residual risks from smoke testing to `docs/tech-debt.md`.

- [ ] **Step 6: Run the complete automated gate**

```powershell
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build:prod
npm.cmd run test:ui
```

Expected: every command PASS without unexplained warnings or snapshot changes.

- [ ] **Step 7: Run the unpacked-extension smoke**

Build and load `dist` in Chrome. Verify:

1. login, registration, 2FA, unlock, PIN, lock, and logout in single mode;
2. Suggestions and All items in the double pane;
3. selection, preserved list scroll, details, copy, reveal, edit, and delete;
4. top-frame and iframe Fill, reprompt refusal, and target-changed failure;
5. generator, health, Sends, account security, accounts, and menus;
6. Options desktop/narrow widths with 18 px icons and no overlap;
7. Receive text/file flows and every embedded surface;
8. keyboard-only use, light/dark mode, 320 px, short height, and 200% zoom;
9. no credential in popup DOM, routes, logs, or Fill responses.

Expected: no inaccessible action, clipping, mixed styling, security regression, or console error.

- [ ] **Step 8: Commit**

```powershell
git add test\ui-render README.md docs\tech-debt.md
git commit -m "test(ui): verify the two-pane extension redesign"
```

---

## Completion Gate

The implementation is complete only when:

- all eight tasks are committed;
- production, not only fixtures, uses approved double/single geometry;
- list context persists while right-pane workflows change;
- all actions and security boundaries remain intact;
- Options has no oversized icon, overlap, or wrapped primary action;
- the repository and bundle contain no reference-product code or assets;
- all automated commands and the unpacked-extension smoke pass;
- every representative screenshot is visually inspected;
- completion receives review through `superpowers:requesting-code-review`;
- integration follows `superpowers:finishing-a-development-branch`.
