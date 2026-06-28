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

Collections grouping, Argon2id accounts, and account registration are not implemented in this milestone.

## User interface

All three surfaces — the popup, the options page, and the in-page autofill popover — share one design system (`src/ui/theme.css`):

- A cool-slate palette with a single indigo accent and a teal "secured" signal. Credential data (usernames, URIs, codes) is set in monospace so machine strings stay unambiguous.
- A full dark theme that follows `prefers-color-scheme`, and motion that respects `prefers-reduced-motion`.
- Iconography is inline SVG and sizing is `rem`-based, so the UI stays crisp and proportional across resolutions, DPI, and browser zoom. The toolbar/extension icon set (16/32/48/128) is generated from a single vector source by `tools/gen-icons.mjs`.
- The options page is a responsive centered column; the popup is a fixed-width panel whose regions scroll within Chrome's height budget; the popover is Shadow-DOM isolated and flips above / clamps to the viewport edge when space is tight.

## Development

```bash
npm.cmd install
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build
```

Load `dist/` from Chrome `chrome://extensions` with Developer Mode enabled.

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
