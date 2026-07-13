# 密屿 MiYu — Vaultwarden Browser Extension

密屿 MiYu is an independent Manifest V3 browser extension that connects Chromium browsers to a
self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (Bitwarden-compatible) server.
All cryptography and vault decryption happen locally in the extension; unlocked key material lives
only in `storage.session` and is cleared on lock, logout, or account switch.

> [!IMPORTANT]
> This project is unofficial and is not affiliated with, endorsed by, or supported by Vaultwarden or
> Bitwarden. Releases are unpacked packages — not signed CRXs, and not distributed through the Chrome
> Web Store or Edge Add-ons. Review the release before using it with a vault you care about.

## Features

- Sign in to a self-hosted Vaultwarden server, with authenticator- and email-based two-factor auth.
- Sync, search, view, create, edit, move, and delete logins, cards, identities, and notes.
- Autofill logins, cards, and identities from the popup, an on-page side panel, the context menu, or a
  focused-fill keyboard shortcut — nothing is ever submitted automatically.
- A dedicated authenticator (2FA) view showing every login's live TOTP with a countdown ring.
- Passkeys: register and sign in with WebAuthn credentials stored in the vault (with an account picker
  when a site has more than one).
- Generate passwords, passphrases, and usernames; check password health and Have I Been Pwned.
- Collections, file attachments, and Vaultwarden Sends.

Targets Chromium MV3 (Chrome / Edge). Firefox and Safari are not supported. Server configurations
vary — test against your own server before relying on it daily.

> **KDF note:** only PBKDF2-HMAC-SHA256 accounts are supported today. Accounts created with Argon2id
> (the current Bitwarden default) cannot yet log in, and fail closed rather than downgrade.

## Install from GitHub Releases

1. Open the [latest release](https://github.com/moooyo/native-chrome-vaultwarden-extension/releases/latest)
   and download `vaultwarden-extension-vX.Y.Z.zip` (and `SHA256SUMS.txt` to verify it).
2. Extract the ZIP into a **permanent** folder — the unpacked extension runs from that folder and must
   stay in place.
3. Open `chrome://extensions` (or `edge://extensions`), enable **Developer mode**, choose **Load
   unpacked**, and select the extracted folder that directly contains `manifest.json`.

The Developer-mode warning is expected for manually loaded extensions.

### Verify the download (Windows PowerShell)

```powershell
$expected = (Get-Content .\SHA256SUMS.txt).Split()[0]
$actual = (Get-FileHash .\vaultwarden-extension-vX.Y.Z.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 checksum mismatch" }
```

No output means the checksum matches.

## First-time setup

1. Open the extension's **Settings** (options page) and, under **Connection**, enter your server's base
   URL, e.g. `https://vault.example.com` (no `/api` or `/identity` suffix). Save it and approve the
   site-access prompt.
2. Open the popup and sign in with your email and master password (complete 2FA if prompted). If the
   server allows it, **Create account** registers a new vault from the login screen.
3. **Sync** if the vault does not populate automatically.

## Update

Unpacked extensions do **not** auto-update. Download and verify the new ZIP, replace the files in your
permanent folder (keep the path), then select **Reload** on the extension card and confirm the version.

## Build from source

Requires Node.js 22 and npm.

```bash
git clone https://github.com/moooyo/native-chrome-vaultwarden-extension.git
cd native-chrome-vaultwarden-extension
npm ci
npm run build:prod     # outputs dist/ — load it with "Load unpacked"
```

## Development

```bash
npm run lint
npm run typecheck
npm test               # unit tests (vitest)
npm run build          # dev build with sourcemaps
npm run test:ui        # smoke the built extension in real Chromium (0 console errors)
```

Live / end-to-end tests (`test/live/`, `npm run verify:e2e`, `npm run seed:testvault`) need a
Vaultwarden test server you configure yourself via `MIYU_SERVER` / `MIYU_EMAIL` / `MIYU_PASSWORD`, and
are skipped by default. `npm run serve:testpage` serves a local autofill/passkey test page at
`http://localhost:8770`. Never commit real server addresses or credentials.

## Release (maintainers)

Git tags are the only release trigger. Set the same `X.Y.Z` in `package.json` and `src/manifest.json`,
commit, verify with `npm run release:prepare -- --tag vX.Y.Z`, then push an annotated tag:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

The Release workflow checks out the tag, runs lint / typecheck / tests / production build, packages a
root-manifest ZIP, writes `SHA256SUMS.txt`, and publishes both to GitHub Releases. A `-beta.N` tag
becomes a prerelease while its package/manifest version stays `X.Y.Z`.

## Security

Treat this as security-sensitive software: install only artifacts from this repository's releases,
verify checksums, keep the browser and server updated, and lock the vault when idle. Report suspected
vulnerabilities privately via the repository's GitHub security advisory — never include master
passwords, tokens, vault exports, TOTP secrets, or real credentials in a public issue.

## License

No license file is currently included. Until one is added, copyright law reserves all reuse and
redistribution rights.
