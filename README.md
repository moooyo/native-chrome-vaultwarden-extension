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
- Autofill logins, cards, and identities from the popup, context menu, or focused-fill keyboard
  shortcut. When inline suggestions are enabled, focusing a recognized field opens the on-page
  chooser. Nothing is ever submitted automatically.
- A dedicated authenticator (2FA) view showing every login's live TOTP with a countdown ring.
- Website passkeys are disabled by default. After enabling the feature in Settings and granting
  website access, register and sign in with WebAuthn credentials stored in the vault. Requests that
  require user verification are left to the browser or OS authenticator.
- Generate passwords, passphrases, and usernames; check password health and Have I Been Pwned. The
  inline registration generator fills the page, then the normal save or update prompt follows only
  when the website form is submitted.
- Collections, file attachments, and Vaultwarden Sends.

Targets Chromium MV3 (Chrome / Edge). Firefox and Safari are not supported. Server configurations
vary — test against your own server before relying on it daily.

> **KDF note:** PBKDF2-HMAC-SHA256 and Argon2id accounts are supported. KDF parameters are validated
> before derivation, and Argon2id work is serialized to keep concurrent operations within its memory budget.

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

Live / end-to-end checks (`test/live/`, `npm run verify:e2e`, `npm run seed:testvault`) need a
Vaultwarden test server you configure yourself via `MIYU_SERVER` / `MIYU_EMAIL` / `MIYU_PASSWORD`.
Files under `test/live/` are excluded from the unit-test suite; run that suite only through
`npm run test:live` after explicitly setting `LIVE=1` (`$env:LIVE = '1'` in PowerShell). The other
commands remain separate entry points. `npm run serve:testpage` serves a local autofill/passkey test
page at `http://localhost:8770`. Never commit real server addresses or credentials.

## Release (maintainers)

Git tags are the only release trigger. Set the same `X.Y.Z` in `package.json` and `src/manifest.json`,
commit, verify with `npm run release:prepare -- --tag vX.Y.Z`, then push an annotated tag:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

The Release workflow checks out the tag without persisted credentials, runs lint / typecheck / unit
tests / production build / Chromium smoke, packages a root-manifest ZIP, and writes `SHA256SUMS.txt`
in a read-only verification job. A separate publish job only downloads those verified assets and
creates the GitHub Release. Re-running an existing release is a no-op only when its tag commit,
prerelease state, asset names, and asset digests are identical; any mismatch fails closed. A
`-beta.N` tag becomes a prerelease while its package/manifest version stays `X.Y.Z`.

## Security

Treat this as security-sensitive software: install only artifacts from this repository's releases,
verify checksums, keep the browser and server updated, and lock the vault when idle. Report suspected
vulnerabilities privately via the repository's GitHub security advisory — never include master
passwords, tokens, vault exports, TOTP secrets, or real credentials in a public issue.

## License

No license file is currently included. Until one is added, copyright law reserves all reuse and
redistribution rights.
