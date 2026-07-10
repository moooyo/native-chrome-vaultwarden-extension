# Native Vaultwarden Browser Extension

Native Manifest V3 browser extension for a self-hosted Vaultwarden server. The extension uses the WebExtensions API with TypeScript and no frontend framework.

## Scope

M1-M3 provides:

- PBKDF2-HMAC-SHA256 login derivation, Bitwarden-style Master Password Hash, HKDF-Expand stretching, EncString encType=2 decrypt with MAC verification before AES-CBC decrypt.
- Vaultwarden prelogin, password grant, Authenticator/Email 2FA branch, refresh token, and sync API calls.
- MV3 service worker-centered session management with UserKey stored only in `storage.session`.
- Read-only vault sync, search, detail view, and on-demand password copy.

M4 adds:

- Native content-script autofill on `http://*/*` and `https://*/*` pages, including all frames.
- Bitwarden-like URI match strategies: Domain, Host, Starts With, Exact, Regular Expression, and Never.
- Semi-automatic form-side popover: credentials are filled only after user selection and forms are never auto-submitted.

Beyond the milestones, the extension now also:

- Decrypts organization-owned ciphers by unwrapping each organization key (RSA-OAEP-SHA1, encType=4) with the account private key, so org logins appear in the list and participate in autofill.
- Generates RFC 6238 TOTP codes for logins that store a TOTP secret (base32 or `otpauth://`), shown with a live countdown in the login detail. The secret is decrypted only in the service worker; only the current code crosses to the popup.
- Includes a password generator (configurable length, character sets, and ambiguous-character avoidance) reachable from the vault toolbar, using `crypto.getRandomValues` with rejection sampling.

Collections grouping, Argon2id accounts, and account registration are not implemented in this milestone.

## User interface

All surfaces — the popup, the options page, the Receive page, and the in-page autofill surfaces — are built from one **Lit 3 component system** (`src/ui/components/`, with `themeTokens` design tokens and shared control styles). Each surface's production entry file (`src/ui/{popup,options,receive}/*.ts`) is a thin dependency adapter that mounts a single Lit root; there is no imperative string renderer and no shared `theme.css`.

- **Popup** — an unlocked **600 x 450 px two-pane workspace** (`vw-popup-app`): the 260 px credential list remains visible while the 340 px detail/workflow pane changes. Authentication and constrained layouts use a **350 x 450 px single-pane** flow. The vault opens on **Suggestions** for the active tab, with All items, search, folders, collections, and trash available without losing list context. Direct Fill remains worker-coordinated, never submits the form, and never places credentials in popup state.
- **Options** — a **settings rail** (`vw-options-app`): Connection, Security, Autofill, Data, and About sections, collapsing to a single selector on narrow viewports.
- **Receive** — `vw-receive-app` accesses and decrypts a Vaultwarden Send (text or file) entirely on-device.
- **In-page surfaces** — the autofill popover, save/update bar, self-dismissing notice, and passkey consent/registration dialogs each render inside a **closed** Shadow Root the page cannot read or forge; every privileged click is gated on `Event.isTrusted`.
- A full dark theme follows `prefers-color-scheme`, motion respects `prefers-reduced-motion`, and iconography is inline SVG with explicit role sizes. Rendered-UI regression coverage verifies exact 600/350 popup geometry, 260/340 pane widths, overflow at 320/404/768 px, long text, dark mode, keyboard focus, 200% zoom, and representative visual snapshots under `npm.cmd run test:ui`.

## Development

```bash
npm.cmd install
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run test:ui
npm.cmd run build
```

`npm.cmd run build:prod` produces the shippable bundle and runs `tools/assert-build.mjs`, which fails the build unless every surface has been switched to its Lit root (independent MV3-CSP-compatible bundles, no shared code splitting, no `theme.css`, no imperative renderer). Load `dist/` from Chrome `chrome://extensions` with Developer Mode enabled.

## Manual acceptance

1. Start or point to a Vaultwarden server and create an existing account with PBKDF2 KDF.
2. Build the extension with `npm.cmd run build`.
3. Load `dist/` as an unpacked extension.
4. Open Options and save the Vaultwarden base URL, approving the host permission prompt.
5. Open the popup and log in with email + master password.
6. If the server requires 2FA, complete Authenticator or Email login.
7. Click Sync and confirm personal login ciphers are listed.
8. Search by item name, username, and URI.
9. Open a login item and copy the password.
10. Keep the popup open for 60 seconds and confirm the clipboard clears if the value is unchanged (best-effort: clearing only occurs while the popup document remains open).
11. Click Lock, reopen the popup, unlock with the master password, and confirm cached items are available.
12. Log out and confirm the popup returns to the login form.
13. Confirm Options exposes the default URI match strategy and defaults to Base domain / Domain.
14. Open a website with one matching login item and confirm the Vaultwarden popover appears near the password field.
15. Click the matching login item and confirm username/password fill without submitting the form.
16. Open a website with multiple matching login items and confirm favorites and stronger match types are listed first.
17. Open a website with no matching login item and confirm the popover reports no matching logins.
18. Lock the vault, reload a login page, and confirm the popover reports locked without showing or filling credentials.
19. Test an iframe login page and confirm matching uses the iframe URL, not the top-level page URL.
20. Confirm hidden, disabled, and readonly fields are not filled.
21. Switch the OS/browser to dark mode and confirm the popup, options page, and popover all adopt the dark theme.
22. Set the display to a HiDPI scale (e.g. 150% / 200%) and confirm icons and text stay crisp in all surfaces.
23. Narrow the options tab and confirm the layout reflows without horizontal scrolling.
24. Open a login that stores a TOTP secret and confirm the verification code shows with a countdown, rolls over at the end of its window, and copies on demand.
25. Open the password generator from the vault toolbar, adjust length and character sets, and confirm a matching password generates, regenerates, and copies.
