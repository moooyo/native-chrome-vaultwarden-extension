# Native Vaultwarden Browser Extension

Native Manifest V3 browser extension for a self-hosted Vaultwarden server. The extension uses the WebExtensions API with TypeScript and no frontend framework.

## Scope

M1-M3 provides:

- PBKDF2-HMAC-SHA256 login derivation, Bitwarden-style Master Password Hash, HKDF-Expand stretching, EncString encType=2 decrypt with MAC verification before AES-CBC decrypt.
- Vaultwarden prelogin, password grant, Authenticator/Email 2FA branch, refresh token, and sync API calls.
- MV3 service worker-centered session management with UserKey stored only in `storage.session`.
- Read-only vault sync, search, detail view, and on-demand password copy.

Organization ciphers and Argon2id accounts are not decrypted in this milestone.

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
