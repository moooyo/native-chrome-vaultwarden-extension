# UI Layout Review and Hardening Design

## Context

The extension exposes four UI families:

- the 360 px browser-action popup;
- the full-tab Options and Receive pages;
- the in-page autofill popover, save bar, and notice;
- the in-page passkey consent and registration dialogs.

The current visual language is coherent: all extension pages use the cool-slate/indigo theme in `src/ui/theme.css`, content-script surfaces mirror that palette inside isolated Shadow DOM roots, dark mode is supported, and reduced-motion preferences are respected. The review found several structural layout risks that are independent of the visual theme:

1. The popup puts a search field and seven 32 px icon buttons in one 328 px content row. The controls cannot all retain a useful width at the declared 360 px popup width.
2. The popup footer puts five labeled controls in one row. Their intrinsic text and padding exceed the available width.
3. Popup authentication and editor screens do not consistently own a scroll region, so short viewports or browser zoom can make lower controls unreachable.
4. `receive.html` uses the Options page's `.page`, `.page-head`, `.settings`, `.settings-head`, and `.actions` classes but does not load the stylesheet that defines them.
5. Autofill and passkey candidate lists have no viewport-relative height limit. Long lists can extend past the viewport.
6. The autofill positioning algorithm clamps horizontally, but it does not clamp the final vertical position when neither side of the anchor has enough room.
7. The save bar and notice need explicit narrow-screen and long-text behavior.

## Goals

- Preserve the existing design system and all current product behavior.
- Make every primary control reachable without unintended horizontal scrolling.
- Give each variable-length region an explicit wrapping, truncation, or scrolling policy.
- Keep popup behavior stable at its normal 360 px width and usable when the available CSS viewport narrows or its height is constrained.
- Keep Options and Receive usable at 320 px and above while retaining their 40 rem maximum content width.
- Keep all content-script UI inside its current Shadow DOM security boundary.
- Verify the repaired layouts through automated invariants and real rendered geometry.

## Non-goals

- Redesigning the palette, typography, icon set, or information architecture.
- Changing authentication, sync, vault, autofill, Send, or passkey data flows.
- Splitting the large popup controller into feature modules. That is useful follow-up work but is not required to repair the identified layout defects.
- Adding a new component framework or runtime dependency.

## Layout Architecture

### Shared full-page shell

Add `src/ui/page.css` for layout shared by Options and Receive. It owns the centered `.page` container, page header, settings card spacing, action row, status toast, and footer rules that currently live in `options.css`. Both HTML pages load `theme.css`, then `page.css`, then their page-specific stylesheet. `options.css` remains the location for Options-only rules; `receive.css` continues to own Send result presentation.

`build.mjs` copies `page.css` to `dist/ui/page.css` with the other static UI assets. A production-build assertion verifies the file and both HTML references are present.

### Popup regions

The popup remains a compact fixed-width instrument, with its width expressed in rem and capped by the available viewport. `#app` clips outer overflow and delegates scrolling to the active content region.

The unlocked shell uses five vertical regions:

1. the existing brand/state app bar;
2. a full-width search row;
3. an equal-width action grid containing Add, Password health, Generator, Sends, Sync, Trash, and Lock;
4. filters, banners, and the vault list, with the list taking remaining height and scrolling independently;
5. a footer with a three-column ordinary-tool grid, status output, and a separate full-width Log out control.

The action IDs, order of event binding, labels, titles, and accessible names remain unchanged. Only wrapper elements and layout classes change.

Authentication, registration, 2FA, unlock, detail, editor, health, Send, account, and confirmation views receive `min-height: 0` and the appropriate `overflow-y: auto` boundary. Focus outlines receive enough inset or surrounding space that scrolling containers do not crop them.

### In-page surfaces

The autofill popover gets a viewport-relative width and maximum height. Its candidate list is the only scrolling child; the brand row stays visible. The positioning function computes the preferred side, then clamps the final top coordinate between the viewport margins. This handles anchors for which neither the space above nor below can contain the whole panel.

The passkey overlay becomes vertically scrollable on short screens. Its card is capped to the viewport, and the registration target list scrolls independently so Cancel and the primary action remain reachable.

The save bar receives an explicit width rather than only a maximum width. At narrow widths it wraps into a message row and an action row without shrinking buttons below their readable size. The notice caps itself against the viewport and uses overflow wrapping for long unbroken text.

## Responsive and Accessibility Rules

- No designed surface may create document-level horizontal overflow at 320 px CSS width.
- Flex and grid children that contain user-controlled strings use `min-width: 0`.
- User-controlled identifiers use ellipsis when they are secondary labels and `overflow-wrap`/`word-break` when the full value must remain readable.
- Long candidate collections scroll within the panel; headers and primary/cancel actions remain visible.
- Icon-only popup actions retain both `title` and `aria-label`.
- Existing visible focus treatment remains present and is not clipped.
- Dark-mode colors and `prefers-reduced-motion` behavior remain unchanged.
- Shadow roots remain closed where they are closed today, and page-controlled strings continue to be escaped or assigned through `textContent`.

## Data Flow and Error Handling

This change has no protocol or state-flow changes. Existing element IDs stay stable so current event listeners and asynchronous status updates address the same nodes. Requests, loading states, failures, and retry behavior remain unchanged.

Layout failure is handled through deterministic CSS policies rather than JavaScript fallbacks:

- fixed controls do not shrink below their usable size;
- flexible text children are allowed to shrink;
- variable-height content scrolls locally;
- long values wrap or truncate according to whether their full value is required;
- viewport-positioned surfaces are clamped on both axes.

## Verification Strategy

### Automated checks

Add focused tests for behavior that can be asserted without a browser renderer:

- the popup unlocked-shell markup separates search and action containers while preserving every existing control ID and accessible label;
- Options and Receive both reference the shared page stylesheet;
- the build includes `dist/ui/page.css`;
- the autofill vertical-position calculation clamps panels to viewport margins for below, above, and constrained placements;
- content surfaces include the required scroll containers and keep existing trusted-click behavior intact.

Run the full project gates after implementation:

```text
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build:prod
```

### Rendered checks

Inspect real rendered geometry for:

- popup login, registration/2FA, unlock, unlocked list, detail, editor, generator, and footer states;
- Options and Receive pages;
- autofill trigger/status/candidate states, including a long candidate list;
- save bar, notice, passkey consent, and a long passkey target list.

Use 320, 360, and 640 px CSS widths where applicable, a short viewport, light and dark color schemes, keyboard-only navigation, and 200% browser zoom. For each state, verify:

- no unintended document-level horizontal overflow;
- all primary and cancellation controls are reachable;
- the expected region, rather than the entire document, owns scrolling;
- focus indicators remain visible;
- content does not overlap or escape its surface;
- the visual hierarchy remains consistent with the existing theme.

## Acceptance Criteria

1. The popup search input has a usable full row, and all seven toolbar actions fit in a distinct action grid at 360 px.
2. All five footer tools fit without clipping or horizontal scrolling, and Log out remains visually separate.
3. Every popup state remains usable in a height-constrained viewport through local vertical scrolling.
4. Receive has the same centered, responsive page shell as Options.
5. Autofill and passkey panels stay within an 8 px/16 px viewport margin respectively, and long candidate lists scroll locally.
6. Save Bar and Notice remain within a 320 px viewport and handle long text.
7. Existing dark mode, reduced motion, keyboard focus, accessible labels, trusted-click checks, and closed Shadow DOM boundaries are preserved.
8. The complete automated test, typecheck, lint, and production-build gates pass.
9. Rendered checks cover the declared surfaces and viewport/theme variants with no unexplained overflow or inaccessible controls.
