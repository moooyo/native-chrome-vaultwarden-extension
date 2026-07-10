# 1Password-Aligned Extension UI Design

## Status

Approved in the interactive design review on 2026-07-11. The user approved the
visual direction, cross-surface scope, 600 x 450 popup framework, and state and
interaction rules.

This specification refines the visual and interaction layer delivered by
`2026-07-10-lit-ui-redesign-and-contextual-fill-design.md`. It does not replace
that document's Lit architecture, security boundaries, feature inventory, or
contextual-fill protocol.

## Context

The extension already uses Lit across the popup, Options, Receive, and embedded
page surfaces. Its current UI is functional, but it reads as a generic compact
form system. The popup is a 404 px single-column surface, item details require
navigation away from the list, and the Options visual baseline contains a
verified icon-sizing and content-overlap defect.

The requested direction is the current 1Password browser-extension product
language. The public Chrome Web Store release was downloaded solely as a design
reference. Inspection of release `8.12.26.40` established these observable
facts:

- the default popup uses a 600 x 450 CSS px double-pane window;
- a 350 x 450 CSS px single-pane window is supported;
- the primary type scale is 14 px body and 12 px secondary text;
- the geometry scale centers on 4, 8, and 12 px radii;
- the spacing scale uses 4, 8, 12, 16, 24, and 32 px increments;
- the interaction language uses a saturated blue, pale blue row selection,
  crisp neutral borders, and strong black text;
- common transitions use 75 ms and 175 ms durations.

These facts guide an original Vaultwarden implementation. No 1Password source
code, compiled modules, font files, icons, images, logos, copy, or proprietary
assets will enter the repository or production bundle.

## Product Goal

Make the extension feel like a focused, mature password-management workspace:
users can scan credentials, retain list context, inspect a selected item, and
fill or copy data without repeatedly navigating between full-screen popup
views.

The primary popup job is:

1. identify the current site or desired vault item;
2. select the correct credential;
3. inspect enough context to confirm the selection;
4. fill or perform a field-level action.

## Non-Goals

- Reimplementing 1Password or reproducing its brand identity.
- Importing Inter, iA Writer Mono, or any font from the reference package.
- Copying reference CSS, JavaScript, SVG paths, screenshots, or product copy.
- Changing vault cryptography, authentication, sync, autofill matching, Sends,
  passkey protocols, or background messaging contracts.
- Adding a full-tab vault application or a dashboard.
- Removing any currently reachable Vaultwarden feature.

## Visual Contract

### Color

The system uses one dominant blue family and neutral structure. Blue carries
primary actions, selection, links, and focus. Success, warning, and destructive
colors appear only for their semantic states.

Light-mode foundation:

- `--vw-ink`: `rgb(0 0 0 / 82%)`;
- `--vw-ink-strong`: `#090A0C`;
- `--vw-muted`: `rgb(0 0 0 / 62%)`;
- `--vw-disabled`: `rgb(0 0 0 / 36%)`;
- `--vw-panel`: `#FFFFFF`;
- `--vw-canvas`: `#FAFAFA`;
- `--vw-blue`: `hsl(212 96% 47%)`;
- `--vw-blue-hover`: `hsl(216 100% 39%)`;
- `--vw-blue-pressed`: `hsl(224 100% 33%)`;
- `--vw-blue-text`: `hsl(212 100% 35%)`;
- `--vw-blue-weak`: `hsl(214 100% 96%)`;
- `--vw-row-selected`: `hsl(215 100% 94%)`;
- `--vw-line`: `rgb(0 0 0 / 13%)`;
- `--vw-line-weak`: `rgb(0 0 0 / 7%)`.

Dark mode defines semantic equivalents instead of inverting light values. It
uses near-black neutral surfaces, 89% white primary text, 78.5% white secondary
text, a dark navy selected row, and a lighter blue for readable links and focus.

### Typography

Use local system fonts only:

- UI and headings: `"Segoe UI Variable Text"`, `"Segoe UI Variable"`,
  `"Segoe UI"`, `system-ui`, `sans-serif`;
- machine values: `"Cascadia Code"`, `Consolas`, `ui-monospace`, `monospace`.

The compact popup scale is 20 px for item titles, 16 px for view titles, 14 px
for body and controls, and 12 px for metadata and field labels. Weight, not
oversized text, establishes hierarchy. Letter spacing remains zero.

### Geometry and Motion

- radii: 4 px small, 8 px control and row, 12 px modal and large surface;
- spacing: 4, 8, 12, 16, 24, and 32 px;
- compact interactive targets: at least 32 x 32 CSS px;
- list rows: 52-54 CSS px with a stable icon column;
- field groups use one outer 8 px border and internal dividers, not nested
  cards;
- fast feedback: 75 ms; normal selection and panel transitions: 175 ms;
- `prefers-reduced-motion` reduces both durations to zero.

Shadows are reserved for floating menus, dialogs, and page-embedded popovers.
Static page sections and popup panes use borders and background contrast.

## Popup Architecture

### Double-Pane Mode

The default unlocked popup is 600 x 450 CSS px. Its structure is:

```text
+----------------------+---------------------------------------+
| Account              | Search vault              New item   |
+----------------------+---------------------------------------+
| Suggestions/All items| Selected item / focused workflow      |
| Credential list      | Detail fields, actions, editor, tool  |
|                      |                                       |
+----------------------+---------------------------------------+
```

The top toolbar is fixed. The left pane is 260 px and the right pane consumes
the remaining 340 px. A 1 px divider separates them. Each pane owns its scroll
region; the popup document itself never scrolls.

The left pane contains scope/filter navigation and compact rows. The right pane
shows the selected item's detail by default. Selecting a row updates the right
pane while preserving the list's scroll position and visible selection.

The right-pane toolbar identifies the active vault or collection context and
contains the primary `Open & Fill` or `Fill` command. Secondary actions live in
field controls or an overflow menu.

Suggestions remain the initial scope when the active page is eligible. All
items remains directly reachable. Browser-derived site context is presented as
plain text and icon metadata; no invented decorative trust rail is used.

### Single-Pane Mode

The popup uses a 350 x 450 CSS px single-pane layout for authentication,
unlock, PIN, 2FA, constrained windows, and the tested high-zoom fallback.
Single-pane unlocked navigation retains Suggestions and All items. Selecting an
item navigates to detail and exposes a semantic Back button with focus return.

At 320 CSS px, the layout caps itself to `100vw` and preserves all commands.
Long account names, item names, usernames, and URLs truncate or wrap according
to whether the complete value is operationally required.

### Focused Workflows

Create, edit, generator, Sends, account security, PIN, and destructive
confirmation workflows occupy the right pane while preserving list context.
When the workflow cannot be understood safely at 340 px, it uses a modal or the
single-pane route; it does not squeeze controls into a third nested column.

Authentication routes always use the centered single-pane window. They never
render an empty list pane.

## Popup Components

### Toolbar

- Account control on the left with vault identity and menu affordance.
- Search centered in the available space.
- `New item` is the only persistent text-and-icon command in the toolbar.
- Tools and account actions remain in grouped menus.
- Icon-only controls use the existing static icon system and tooltips.

### Vault Rows

- Fixed icon column, title, one secondary identifier, and optional status.
- Selected row uses the blue selection color with contrast-safe inverse text.
- Hover uses a weak blue or neutral surface and never resembles selection.
- Focus remains independently visible with a 2 px blue outline.
- Favorite and protected states use compact semantic indicators.
- IDs and secrets never appear in DOM attributes.

### Item Detail

- A 46-48 px item glyph, 20 px title, type, and favorite indicator lead the
  detail.
- Related values sit in bordered field groups with internal dividers.
- Labels use 12 px readable blue; values use 14 px neutral text.
- Passwords, TOTP codes, recovery values, and machine strings use the monospace
  stack.
- Copy, reveal, open, and history controls remain adjacent to their field.
- Edit, move, delete, and other structural commands stay in the toolbar menu.

### Editors and Tools

Editors use one vertical form flow with stable labels and 36 px inputs. The
action row remains reachable at the bottom of the right pane. Tool views reuse
the same right-pane title bar, scroll container, status handling, and Back or
close behavior.

## Full-Page Surfaces

### Options

Options adopts the same high-contrast typography, saturated blue, 8 px
selection geometry, and neutral dividers without imitating the popup's fixed
size.

It uses a white navigation rail with 18 px icons and solid blue selection, plus
a white or very light neutral content workspace. Setting groups use pale-blue
headers only when they label a real semantic group. Individual settings use a
two-column workbench row: label and explanation on the left, control or state on
the right. Below 640 px, rows stack and the rail becomes the existing selector.

All icons receive explicit width and height. The redesign must eliminate the
current oversized icon, content overlap, and wrapped primary-button defect.

### Receive

Receive reuses the Options page header, type, controls, and field groups without
the settings rail. It remains a single-purpose flow with a constrained content
column and clear access, password-required, text-ready, file-ready, downloading,
and error states.

## Embedded Page Surfaces

Autofill popovers, save bars, notices, and passkey dialogs reuse the same 14/12
px type scale, 8 px row/control radius, blue primary action, neutral borders,
and selected-row language. They remain compact and page-aware rather than
copying the popup panes.

Page-facing components remain in closed Shadow DOM. Trusted-event checks,
callback boundaries, viewport clamping, and the prohibition on secret IDs in
DOM attributes remain unchanged.

## State and Error Handling

- Loading uses stable skeleton rows and never changes pane dimensions.
- Empty states explain the next available action without decorative artwork.
- Operation errors stay beside the command that produced them.
- Locked, logged-out, and account-switched states clear item selection and all
  secret component state.
- A removed or no-longer-matching item clears the detail pane and selects the
  nearest valid row only when that behavior is unambiguous.
- Fill outcomes preserve the existing typed protocol and never render a
  success-shaped fallback.
- Menus and dialogs restore focus to their invoking controls.

## Accessibility and Responsive Behavior

- Native buttons, inputs, links, menus, tabs, and dialogs retain semantic roles
  and accessible names.
- Arrow keys move through the credential list; Enter opens/selects; Escape
  closes transient UI or returns from a single-pane detail.
- Tab order follows the visible pane order and does not enter hidden controls.
- Selection and focus are separate visual states.
- Normal text meets WCAG 2.1 AA 4.5:1 contrast; controls and indicators meet
  applicable non-text contrast.
- Popup panes retain visible focus at scroll boundaries.
- No surface creates document-level horizontal overflow at 320 CSS px.
- Controls remain reachable in short viewports and at the existing 200% zoom
  geometry test.

## Testing Strategy

### Component Tests

Add or update Vitest coverage for:

- double-pane list selection and right-pane detail updates;
- preserved list scroll and selection across detail actions;
- single-pane Back navigation and focus restoration;
- auth routes selecting single-pane mode;
- lock, logout, and account switch clearing selection and secret state;
- toolbar action placement and menu grouping;
- loading, empty, error, long-text, and focused workflow states;
- Options rail icon sizing and setting-row structure.

### Rendered Browser Tests

Update Playwright fixtures and visual baselines for:

- 600 x 450 double-pane Suggestions, All items, detail, editor, and tools;
- 350 x 450 single-pane auth, Suggestions, detail, and Back navigation;
- 320 px constrained width and existing 200% zoom geometry;
- short height, long unbroken text, light mode, and dark mode;
- list and detail independently owning scroll;
- focus visibility on selected and unselected rows;
- Options at desktop and narrow widths;
- Receive and all embedded page surfaces.

Geometry assertions remain more authoritative than screenshots. Screenshot
baselines cover representative families and approved hierarchy, not every
state permutation.

### Project Gates

The redesign is complete only after these commands pass:

```text
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build:prod
npm.cmd run test:ui
```

A real unpacked-extension smoke must also cover unlocked Suggestions, All
items, double-pane selection, item detail, edit, top-frame and iframe Fill,
auth single-pane routes, Options, Receive, embedded surfaces, keyboard-only
operation, dark mode, and zoom.

## Acceptance Criteria

1. The default unlocked popup is a 600 x 450 double-pane workspace with a
   260 px list pane and a 340 px detail/workflow pane.
2. Authentication and constrained layouts use a functional 350 x 450
   single-pane mode, capped safely at 100vw.
3. Selecting a credential preserves list context and renders its detail in the
   right pane without routing the entire popup away.
4. `Open & Fill` or `Fill` is the right pane's sole primary command; secondary
   actions retain field or menu proximity.
5. Popup and full-page surfaces use the approved high-contrast neutral and
   saturated-blue visual system, 14/12 px compact type scale, and 4/8/12 px
   radius scale.
6. The repository contains no copied 1Password code, fonts, icons, images,
   logos, screenshots, product copy, or other proprietary assets.
7. Options has fixed-size navigation icons, no content overlap, and no wrapped
   primary-button defect at supported widths.
8. All existing Vaultwarden actions and security boundaries remain intact.
9. Light mode, dark mode, keyboard focus, reduced motion, long text, short
   viewports, 320 px width, and 200% zoom are covered by automated tests.
10. Unit tests, typecheck, lint, production build, Playwright tests, and the
    real-extension smoke pass before completion.
