# Popup Intrinsic Size Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Chrome open the extension popup at 350 x 450 CSS pixels for authentication and 600 x 450 CSS pixels for the unlocked workspace.

**Architecture:** Give `VwPopupFrame` intrinsic, mode-owned geometry instead of constraining it to the provisional extension viewport. Keep route-owned layout selection in `VwPopupApp`, but remove startup `matchMedia` state so an initially tiny Chrome popup cannot force the application into single-pane mode.

**Tech Stack:** TypeScript 6, Lit 3, Vitest, happy-dom, Playwright, esbuild, Chrome Manifest V3

## Global Constraints

- `auth` and `single` modes are exactly 350 x 450 CSS pixels.
- `double` mode is exactly 600 x 450 CSS pixels.
- Popup width and height must not derive from `100vw` or `100vh` during extension startup.
- Internal panes retain local scrolling with `min-width: 0` and `min-height: 0`.
- Do not change vault state, navigation, authentication, permissions, visual styling, or business behavior.

---

## File Structure

- `src/ui/popup/popup-frame.ts` owns intrinsic popup geometry for each explicit layout mode.
- `src/ui/popup/popup-frame.test.ts` owns the component-level geometry regression contract.
- `src/ui/popup/app.ts` owns route-to-layout selection without viewport-derived startup state.
- `src/ui/popup/app.test.ts` owns the application-level unlocked/auth mode regression contract.
- `src/ui/popup/popup.css` owns only document framing and must not impose a competing size.
- `test/ui-render/layout.spec.ts` owns browser-computed geometry and overflow assertions.

### Task 1: Give the popup frame intrinsic geometry

**Files:**
- Modify: `src/ui/popup/popup-frame.test.ts`
- Modify: `src/ui/popup/popup-frame.ts`
- Verify: `test/ui-render/layout.spec.ts`

**Interfaces:**
- Consumes: `PopupLayoutMode = 'double' | 'single' | 'auth'` and the existing geometry custom properties from `themeTokens`.
- Produces: `<vw-popup-frame mode=...>` whose host has an intrinsic width and height independent of viewport units.

- [ ] **Step 1: Write the failing component regression test**

Add this test beside the existing frame mode tests:

```typescript
it('uses intrinsic geometry instead of the provisional extension viewport', () => {
  const cssText = VwPopupFrame.styles.map((style) => style.cssText).join(' ');

  expect(cssText).toContain('width: var(--vw-popup-double-width)');
  expect(cssText).toContain('height: var(--vw-popup-height)');
  expect(cssText).toContain('width: var(--vw-popup-single-width)');
  expect(cssText).not.toContain('100vw');
  expect(cssText).not.toContain('100vh');
});
```

- [ ] **Step 2: Run the test to verify RED**

Run:

```powershell
npm.cmd test -- src\ui\popup\popup-frame.test.ts
```

Expected: FAIL because the stylesheet currently contains `min(..., 100vw)` and `min(..., 100vh)` instead of intrinsic dimensions.

- [ ] **Step 3: Implement intrinsic frame dimensions**

Change the host geometry in `popup-frame.ts` to:

```css
:host {
  display: block;
  width: var(--vw-popup-double-width);
  height: var(--vw-popup-height);
  overflow: hidden;
  background: var(--vw-panel);
}
:host([mode='single']),
:host([mode='auth']) {
  width: var(--vw-popup-single-width);
}
```

Remove the `@media (max-width: 480px)` block from this component. Preserve all pane sizing, box sizing, and local overflow rules unchanged.

- [ ] **Step 4: Run focused component and browser geometry tests**

Run:

```powershell
npm.cmd test -- src\ui\popup\popup-frame.test.ts
npm.cmd run build:ui-fixtures
npx.cmd playwright test test\ui-render\layout.spec.ts
```

Expected: all commands PASS; existing 350 x 450 and 600 x 450 computed-geometry assertions remain green.

- [ ] **Step 5: Commit the frame fix**

```powershell
git add src/ui/popup/popup-frame.ts src/ui/popup/popup-frame.test.ts
git commit -m "fix(popup): give frame intrinsic dimensions"
```

### Task 2: Remove viewport-dependent application layout selection

**Files:**
- Modify: `src/ui/popup/app.test.ts`
- Modify: `src/ui/popup/app.ts`
- Verify: `src/ui/popup/popup.css`

**Interfaces:**
- Consumes: authentication routes, unlocked routes, and the explicit `auth` and `double` frame modes from Task 1.
- Produces: `VwPopupApp` that always renders authentication routes in `auth` mode and unlocked routes in `double` mode without querying viewport width.

- [ ] **Step 1: Write the failing application regression test**

Add a test that provides a narrow `matchMedia` result before connecting the app, then verifies that an unlocked route still uses the intrinsic double frame:

```typescript
it('does not let the provisional popup viewport force unlocked routes into single mode', async () => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({
    matches: true,
    media: '(max-width: 480px)',
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })));
  const app = document.createElement('vw-popup-app') as VwPopupApp;
  app.request = unlockedHandlers();
  document.body.append(app);

  await app.updateComplete;
  await vi.waitFor(() => expect(app.route.name).toBe('vault'));
  await app.updateComplete;

  expect(app.shadowRoot?.querySelector('vw-popup-frame')?.getAttribute('mode')).toBe('double');
});
```

Place this test in the existing unlocked workspace shell describe block, reuse its `unlockedHandlers()` helper, and call `vi.unstubAllGlobals()` from that block's existing `afterEach` cleanup.

- [ ] **Step 2: Run the test to verify RED**

Run:

```powershell
npm.cmd test -- src\ui\popup\app.test.ts
```

Expected: FAIL because `connectedCallback()` reads the narrow media query and renders `mode="single"`.

- [ ] **Step 3: Remove viewport-derived state from the app**

In `app.ts`:

- Remove the reactive `narrow` property and declaration.
- Remove `mediaQuery` and `onNarrowChange` fields.
- Remove the `matchMedia` setup and listener from `connectedCallback()`.
- Remove listener cleanup from `disconnectedCallback()` while preserving ephemeral-state cleanup.
- Make non-authenticated routes return `double` from `layoutMode()`.
- Simplify `renderUnlockedWorkspace()` to always render the existing double-pane frame branch.
- Remove `max-width: 100vw` and `max-height: 100vh` from the app host so the root does not reintroduce viewport-dependent sizing.

The resulting host rule is:

```css
:host {
  display: block;
  min-width: 0;
  width: fit-content;
}
```

Do not change `popup.css`; its `body { width: fit-content; overflow: hidden; }` contract lets the intrinsic frame size the extension document.

- [ ] **Step 4: Run focused tests to verify GREEN**

Run:

```powershell
npm.cmd test -- src\ui\popup\app.test.ts src\ui\popup\popup-frame.test.ts
npm.cmd run typecheck
```

Expected: all tests and TypeScript checks PASS, including auth mode, unlocked mode, navigation, and cleanup tests.

- [ ] **Step 5: Commit application sizing behavior**

```powershell
git add src/ui/popup/app.ts src/ui/popup/app.test.ts
git commit -m "fix(popup): decouple layout from startup viewport"
```

### Task 3: Verify the packaged extension

**Files:**
- Verify: `dist/ui/popup/popup.css`
- Verify: `dist/ui/popup/popup.js`
- Verify: `dist/manifest.json`

**Interfaces:**
- Consumes: the intrinsic frame and viewport-independent app behavior from Tasks 1 and 2.
- Produces: a production extension package whose popup entry contains the corrected geometry behavior.

- [ ] **Step 1: Run the full automated verification suite**

```powershell
npm.cmd test
npm.cmd run test:ui
npm.cmd run lint
npm.cmd run typecheck
npm.cmd run build:prod
```

Expected: every command exits with code 0; visual snapshots remain unchanged because intended 350 x 450 and 600 x 450 rendering is preserved.

- [ ] **Step 2: Inspect the production output contract**

Run:

```powershell
rg -n "100vw|100vh|vw-popup-double-width|vw-popup-single-width|vw-popup-height" dist\ui\popup\popup.js dist\ui\popup\popup.css
```

Expected: popup frame geometry in `popup.js` references the three custom properties and does not combine them with `100vw` or `100vh`. Any viewport units belonging to nested feature components must be reviewed and shown not to control the popup document size.

- [ ] **Step 3: Perform available browser validation**

Reload `dist` as an unpacked extension in Chrome, open the toolbar popup while logged out, and verify a 350 x 450 popup. Sign in or unlock, reopen the popup, and verify a 600 x 450 double-pane workspace with working local pane scrolling.

If no controllable Chrome instance is available, record that limitation explicitly and provide the rebuilt `dist` directory for the user's manual reload check. Do not claim real-browser verification without observing it.

- [ ] **Step 4: Commit any test-only adjustments required by verified behavior**

Only if browser verification exposes a test gap, add the smallest regression assertion, run it RED against the pre-fix revision where practical, then GREEN against the fix. Commit with:

```powershell
git add src/ui/popup test/ui-render
git commit -m "test(popup): cover extension startup geometry"
```
