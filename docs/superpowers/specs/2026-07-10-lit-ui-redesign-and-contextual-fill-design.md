# Lit UI Redesign and Contextual Fill Design

## Status

Design sections approved on 2026-07-10. Written specification awaiting final
user review.

This specification supersedes and replaces
`docs/superpowers/specs/2026-07-10-ui-layout-hardening-design.md`. The earlier
document repaired the existing layout without changing its information
architecture. The approved direction is instead a complete, atomic UI rewrite.

## Context

The extension has four UI families:

- the browser-action popup;
- the full-tab Options and Receive pages;
- the in-page autofill popover, save bar, and notice;
- the in-page passkey consent and registration dialogs.

The current theme is coherent, but the UI has outgrown its original structure.
The popup controller is more than 2,600 lines and renders every state through
imperative `innerHTML` updates. Seven toolbar actions, five footer actions,
filters, list state, editors, generators, Sends, account management, and
security tools compete inside a 360 px panel. Full-page and content-script
surfaces duplicate component styles, and Receive uses layout classes defined
only by the Options stylesheet.

The redesign takes interaction and component-discipline references from the
current 1Password browser product, while retaining an original Vaultwarden
identity. It may adopt task-first search, contextual suggestions, grouped
menus, predictable item rows, and consistent consent composition. It must not
copy 1Password logos, its keyhole mark, proprietary Agile Sans font,
illustrations, exact brand palette, CSS, or source code.

## Goals

- Replace all user-facing surfaces with one coherent Lit 3.x component system.
- Make current-site suggestions the popup's default unlocked task.
- Add a secure, one-click Fill action that supports top-level and iframe forms.
- Preserve every existing feature while reorganizing access to it.
- Keep secrets out of popup component state during direct Fill.
- Keep page-facing UI inside closed Shadow DOM security boundaries.
- Make controls reachable and layouts usable from 320 px through full-tab
  desktop widths, short viewports, dark mode, and browser zoom.
- Deliver the rewrite as one atomic cutover with no committed mixed old/new UI.
- Add rendered browser coverage in addition to the existing unit gates.

## Non-goals

- Reworking authentication, vault encryption, sync, Sends, passkey
  cryptography, or server protocols.
- Implementing roadmap gaps such as Argon2id, organization policies, SSO, or
  additional 2FA providers.
- Adding a desktop companion or biometric unlock.
- Copying another product's brand identity.
- Adding proactive password-health scans or other background work merely to
  populate decorative UI.
- Turning the extension into a general full-tab vault application.

## Approved Product Decisions

### Framework

Use the latest stable Lit 3.x release. Lit is selected because this extension
already depends on browser-native lifecycle, Custom Elements, and closed
Shadow DOM boundaries. It provides reactive rendering without introducing a
virtual DOM and lets popup, full-page, and embedded surfaces share the same
component model.

Do not add a second UI framework. Do not use proprietary or remotely loaded
fonts, scripts, styles, or assets.

### Visual language

The design uses an original light blue system:

- primary blue: `#3267E3`;
- deep interactive blue: `#2454C6`;
- selected/trusted tint: `#F4F7FF`;
- stronger tint: `#E7EEFF`;
- canvas: `#F6F8FB`;
- panel: `#FFFFFF`;
- primary text: `#172033`;
- secondary text: `#677286`;
- border: `#DCE2EB`;
- success remains a restrained teal/green signal;
- destructive states remain red and never reuse the primary blue.

Equivalent dark-mode tokens must preserve hierarchy and WCAG contrast rather
than mechanically invert the light palette.

Use the existing native UI font stack, preferring `Segoe UI Variable` where
available. Keep usernames, URIs, passwords, codes, and other machine strings
in the existing monospace stack.

Blue communicates focus, selection, the product mark, and primary actions. It
must not become a large decorative field. Layout relies on spacing, typography,
and quiet borders before color or shadow. The base radius scale is 8 px for
controls, 10 px for grouped surfaces, and 14 px for the popup shell. Motion is
limited to 120-160 ms state transitions and is disabled by
`prefers-reduced-motion`.

### Atomic cutover

Development may follow dependency order, but old entry points remain active
until all new roots, components, tests, and build changes are ready. The final
change switches every entry point and removes the old rendering code in one
atomic cutover. No commit intended for integration may leave users with a
mixture of old and new UI families.

## Component Architecture

### Shared UI layer

Create a shared Lit component layer under `src/ui/components/`. It owns:

- token styles and dark-mode mappings;
- base buttons, icon buttons, text fields, selects, checkboxes, and status
  messages;
- menus, menu items, dialogs, tabs, list rows, empty states, and loading
  states;
- the Vaultwarden shield mark and shared SVG icon wrappers;
- focus, keyboard, responsive, and reduced-motion behavior;
- common types for explicit async view states.

Shared components expose typed properties and semantic events. They do not call
the background worker directly. Feature roots own data loading and commands so
components remain independently renderable and testable.

CSS custom properties provide token inheritance across extension documents and
closed roots. Each component owns only structural and component-specific CSS.
There must be no unscoped global selectors in content-script surfaces.

### Popup

Replace the imperative popup renderer with a root component and feature
components grouped by responsibility:

- `auth`: login, registration, 2FA, unlock, PIN unlock, and reprompt;
- `vault`: Suggestions, All items, folder/collection filters, trash, and list
  states;
- `item`: login/note/card/identity detail and protected-field reveal;
- `editor`: type selection, create/edit forms, attachments, collections, and
  destructive confirmation;
- `tools`: generator, password health, Sends, account security, and key
  rotation;
- `menus`: account and global tool menus.

The popup root owns the top-level view state, request lifecycle, focus
restoration, and navigation history. Feature components own local form state.
Sensitive local state is cleared when a component is detached, the vault locks,
the account changes, or logout completes.

The popup width is `25.25rem` (404 CSS px at the default 16 px root size) and is
capped at `100vw`. It has one outer scroll boundary and explicit inner
list/editor scroll boundaries. No popup state may create document-level
horizontal scrolling at 320 CSS px.

### Options

Options uses a full-page shell with a settings navigation rail. Initial
sections are:

- Connection: server URL and host-permission save flow;
- Security: lock timeout, idle action, and clipboard clearing;
- Autofill: default URI matching and related browser behavior;
- Data: Import and Export;
- About: extension version and the local-secret security statement.

The Data section receives Import and Export, removing those operations from the
popup footer. Data first reads session state; while locked, its operations are
disabled with an explicit instruction to unlock from the popup. The navigation
rail becomes a compact top selector below the narrow breakpoint. The content
area uses setting rows with labels, descriptions, controls, and local status.
Save behavior remains explicit where permission prompts or coupled settings
require it; existing save-on-change security behavior remains unchanged.

### Receive

Receive reuses the full-page shell, controls, status messages, and responsive
content width without rendering the settings rail. It remains a focused
single-task flow:

1. enter or paste a Send URL;
2. provide a password only when required;
3. inspect text or download a file;
4. surface access and decrypt errors in the result region.

### Content-script surfaces

Rewrite autofill, save, notice, passkey consent, and passkey registration UI as
Lit components. Production hosts continue to attach `mode: 'closed'` shadow
roots and retain direct references internally. Page-controlled strings are
assigned as values or text nodes, never interpolated as unsafe HTML.
Lit's `unsafeHTML` and `unsafeSVG` directives are prohibited for
page-controlled or vault-controlled content.

The page must not be able to inspect component state, invoke privileged
actions, or forge accepted clicks. Existing `Event.isTrusted` checks remain at
the privileged action boundary.

## Popup Information Architecture

### Unlocked header

The header contains:

- an account menu button with the active vault/account identity;
- Password Generator;
- a global tools menu;
- a primary Add item action.

The account menu contains account switching and management, PIN settings,
Options, Lock, and Log out. The global tools menu contains Password Health,
Sends, Trash, and Sync. Import and Export move to Options > Data.

All existing actions remain reachable. Moving an action does not change its
underlying request or confirmation behavior.

### Suggestions and All items

The unlocked popup opens on Suggestions when an eligible HTTP(S) tab is
available. Search remains immediately available. A two-tab scope switch shows:

- Suggestions: items matched to fillable forms in the active tab and its
  frames;
- All items: the complete local vault listing with existing folder,
  collection, type, and text filtering.

When Suggestions cannot be inspected because the page is restricted, site
access is unavailable, no content script is present, or no fillable forms
exist, the popup explains the state and exposes All items. This is a neutral,
recoverable state, not a fake successful result.

A suggestion row has:

- item icon/monogram, name, username, favorite, and protected state;
- a dedicated Fill action when a valid target exists;
- a row action/menu for secondary commands;
- row navigation to item detail.

Reprompt-protected items show a protected state and route the user through the
existing extension-side master-password verification. They are never released
directly to a page.

### Detail and tools

Item detail groups related fields into one quiet content plane. Copy, reveal,
open, and TOTP actions stay adjacent to the value they affect. Destructive or
structural actions remain explicit and separated from copy/reveal actions.

Tool views use the same root shell, title bar, local scroll region, status
model, and back-navigation behavior. The redesign does not create an automatic
password-health scan or cache solely for a dashboard banner.

## Contextual Suggestions and Direct Fill

### Permissions

Add:

- `activeTab`, so invoking the extension grants temporary access to the active
  page without requesting permanent broader access for this feature;
- `webNavigation`, so the background coordinator can enumerate and verify the
  active tab's frames.

Existing host permission and content-script behavior remains unchanged.

### Coordinator

Add a background `TabAutofillCoordinator`. Popup code never trusts or supplies
an authoritative page URL. It supplies only the active tab identifier obtained
from the browser API.

The coordinator:

1. validates that the tab is still active and eligible;
2. obtains current frame identifiers, document identifiers when available, and
   frame URLs from browser APIs;
3. sends an inspection command to each eligible content-script frame;
4. receives only form metadata: stable form identifier, field roles,
   visibility, and recent-focus information; it receives no field values;
5. ranks targets by recent recognized focus, then top-level frame, then visible
   form/document order; "recent" means the newest recognized focus since that
   frame's current document loaded, and timestamps older than 30 seconds do not
   outrank an eligible top-level target;
6. calls the existing URI-matching service with browser-derived frame URLs;
7. deduplicates candidate items while preserving the best valid fill target;
8. returns typed, non-secret suggestion records to the popup.

Suggestions remain useful when a matching item exists but a direct fill target
does not. In that case the row opens detail but does not claim that Fill is
available.

### Fill

When the user activates Fill:

1. the popup sends tab, candidate, and target identifiers, but no URL or
   credentials;
2. the coordinator re-reads the target frame/document and authoritative URL;
3. the worker calls the existing credential-release path, including URI
   matching, session state, and reprompt enforcement;
4. credentials travel directly from the worker/background boundary to the
   selected content-script frame and never enter popup Lit state or DOM;
5. the content script re-resolves the form identifier, verifies the frame URL,
   document, and connected fillable fields, then performs the existing
   synthetic-input fill;
6. the form is never submitted;
7. a typed outcome returns to the popup.

The content script must abort if the document, URL, form, or eligible fields
changed between inspection and commit. Frame and document identifiers are
revalidated rather than treated as durable across navigation or a service
worker restart.

Supported outcomes include:

- filled;
- no eligible tab;
- site access unavailable;
- no fillable target;
- target changed;
- vault locked;
- sync required;
- no longer matched;
- reprompt required;
- restricted page;
- content script unavailable;
- explicit internal error.

Each outcome maps to a user-facing status and a test. Errors are not collapsed
into a generic success-shaped fallback.

## State and Error Handling

Every Lit root and async feature uses an explicit discriminated state:

- `idle`;
- `loading`;
- `ready`;
- `empty`;
- `error`.

Feature operations may define narrower success and failure variants. They do
not use broad exception swallowing. Existing `AppErrorCode` mappings remain
the source of product-facing worker errors. Unexpected responses are rejected
as protocol errors rather than cast to an expected type.

Operation status is rendered beside the operation that produced it. Auth
errors stay with auth forms, Fill outcomes stay in Suggestions, import/export
outcomes stay in Data, and Receive errors stay in its result region.

Menus and dialogs restore focus to their invoking control. Navigation clears
stale operation statuses. Lock, logout, and account switch clear all secret or
account-specific component state.

## Accessibility and Responsive Rules

- All actions use semantic buttons, links, form controls, menus, tabs, or
  dialogs with accessible names.
- Tab lists support arrow keys, Home, End, Enter, and Space.
- Menus support arrow keys, Home, End, Enter, Space, Escape, and focus return.
- Dialogs trap focus, close on Escape where cancellation is safe, and restore
  focus.
- Async statuses use the appropriate `aria-live` politeness.
- Focus indicators remain visible inside every scroll boundary.
- Interactive targets are at least 32 CSS px in the compact desktop UI.
- Normal text meets 4.5:1 contrast; large text and non-text indicators meet
  their applicable WCAG contrast.
- User-controlled secondary identifiers truncate with ellipsis; values that
  must be fully readable wrap with `overflow-wrap` or `word-break`.
- Long lists scroll inside their surface while headers and primary/cancel
  actions remain reachable.
- Popup, Options, Receive, and content surfaces create no unintended horizontal
  overflow at 320 CSS px.
- Existing dark mode and `prefers-reduced-motion` behavior remain supported.

## Testing Strategy

### Unit and service tests

Keep all existing Vitest coverage. Add focused tests for:

- target inspection and ranking across top-level and iframe forms;
- duplicate candidate selection;
- active-tab, restricted-page, and permission failures;
- frame/document/URL/form TOCTOU checks;
- reprompt and URI-match fail-close behavior;
- worker-to-frame credential routing with no credential in popup responses;
- explicit Fill outcomes;
- lock/logout/account-switch secret-state clearing.

### Lit component tests

Render components in the existing happy-dom environment and cover:

- every `idle/loading/ready/empty/error` state;
- Suggestions and All items switching;
- menus and action placement;
- keyboard navigation and focus restoration;
- dialog cancellation and trusted-click boundaries;
- long strings and long candidate collections;
- Options rail narrow-mode behavior;
- Receive access, password, text, and file states;
- autofill, save, notice, consent, and registration component states.

Tests should query roles, labels, and component contracts rather than brittle
full-markup snapshots.

### Rendered browser tests

Add Playwright as a development dependency and create deterministic UI fixture
pages for each root and important state. Use real browser layout to assert:

- 320, 404, and 768 CSS px widths where applicable;
- normal and short viewports;
- light and dark color schemes;
- 200% browser zoom or equivalent CSS geometry;
- no unintended document-level horizontal overflow;
- the intended region owns scrolling;
- fixed headers and action rows remain reachable;
- focus indicators are not clipped;
- dialogs and in-page surfaces remain inside the viewport.

Keep a small set of stable screenshots for the approved visual hierarchy.
Prefer geometry and semantic assertions over a large, noisy snapshot suite.

### Real extension smoke

Build and load the unpacked extension in Chrome against the repository's real
Vaultwarden test environment. Verify:

- login, 2FA path, unlock, lock, and logout;
- sync, Suggestions, All items, search, detail, edit, tools, and menus;
- direct Fill in the top frame and a nested iframe;
- a navigation between inspection and Fill;
- reprompt refusal;
- Options permission saving and all sections;
- Receive text and file flows;
- autofill popover, save bar, notice, passkey consent, and passkey
  registration;
- light/dark mode, keyboard-only use, short viewport, and zoom.

Run the complete project gates:

```text
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build:prod
```

## Build and Dependency Rules

- Add `lit` as a production dependency.
- Add Playwright and its test runner as development dependencies.
- Keep the existing TypeScript/esbuild pipeline and MV3 CSP compatibility.
- Do not load remote runtime assets.
- Do not enable shared ESM chunks for manifest content-script bundles unless a
  verified Chrome loading strategy exists; independent bundled entries are an
  acceptable size tradeoff.
- Production build assertions verify every HTML entry, static stylesheet,
  manifest permission, and generated bundle.

## Acceptance Criteria

1. All popup, Options, Receive, autofill, save, notice, and passkey surfaces are
   Lit-based and use the approved Vaultwarden blue component system.
2. No old imperative UI renderer or duplicate legacy surface remains active.
3. The final branch contains no user-visible mixed old/new UI state.
4. The unlocked popup defaults to current-site Suggestions when an eligible tab
   exists and provides an explicit All items scope.
5. Suggestions support top-level and iframe targets without trusting a
   popup-supplied URL.
6. Fill credentials never enter popup Lit state or DOM, and direct Fill never
   submits a form.
7. Reprompt, URI matching, frame/document navigation, and field-connectivity
   checks fail closed.
8. Every existing product action remains reachable in the approved header,
   account menu, tools menu, feature view, or Options section.
9. Import and Export live under Options > Data and retain their current
   confirmations and security behavior.
10. Options uses the approved settings rail and collapses it at narrow widths;
    Receive reuses the full-page shell without the rail.
11. All content-script surfaces retain closed Shadow DOM and trusted-action
    boundaries.
12. No designed surface creates unintended horizontal overflow at 320 CSS px,
    and all primary/cancel controls remain reachable in short viewports.
13. Keyboard, focus, contrast, dark-mode, reduced-motion, and live-status
    requirements are covered by automated tests.
14. Vitest, typecheck, lint, production build, Playwright geometry tests, and
    the real Chrome/Vaultwarden smoke pass before the atomic cutover is
    considered complete.
