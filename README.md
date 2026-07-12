# Native Vaultwarden Browser Extension

An independent Manifest V3 browser extension for connecting Chromium browsers
to a self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
server. Cryptographic operations and vault decryption happen locally in the
extension.

> [!IMPORTANT]
> This project is unofficial and is not affiliated with, endorsed by, or
> supported by Vaultwarden or Bitwarden. Releases are not signed or distributed
> through the Chrome Web Store or Microsoft Edge Add-ons. Review the release and
> security notes before using it with a production vault.

## Features

- Sign in to a self-hosted Vaultwarden server, including authenticator and email
  two-factor authentication.
- Sync, search, view, create, edit, move, and delete supported vault items.
- Fill logins, cards, and identities from the popup, in-page picker, context
  menu, or focused-fill keyboard shortcut.
- Generate passwords, passphrases, usernames, and TOTP verification codes.
- Work with collections, file attachments, Vaultwarden Sends, passkeys, password
  health, and Have I Been Pwned password checks.
- Store unlocked key material in browser session storage and clear sensitive
  state on lock, logout, or account change.

The extension currently targets Chromium Manifest V3. Firefox and Safari are
not supported. Vaultwarden configurations and server versions vary; test the
extension with your server before relying on it for daily access.

## Requirements

- Google Chrome or Microsoft Edge with Manifest V3 and Developer mode support.
- A reachable Vaultwarden server using HTTPS. Plain HTTP should only be used for
  local development on a trusted machine.
- An existing Vaultwarden account, or a server that permits new account
  registration through the extension's **Create account** flow.
- A permanent folder where the unpacked extension can remain installed.

## Install from GitHub Releases

1. Open the [latest GitHub Release](https://github.com/moooyo/native-chrome-vaultwarden-extension/releases/latest).
2. Under **Assets**, download `vaultwarden-extension-vX.Y.Z.zip`.
3. Optionally download `SHA256SUMS.txt` and verify the archive as described
   below.
4. Extract the ZIP into a permanent folder, for example
   `C:\Users\YourName\Applications\VaultwardenExtension`.
5. Follow the Chrome or Edge instructions below and select that extracted
   folder.

Do not drag the ZIP onto the browser's extension page. The release archive is
an unpacked-extension package, not a store-signed CRX. It must be extracted
first, and the extracted folder must remain in place while the extension is
installed.

### Verify the download on Windows

Place the ZIP and `SHA256SUMS.txt` in the same directory. Open PowerShell in
that directory, replace `vX.Y.Z` with the downloaded version, and run:

```powershell
$expected = (Get-Content .\SHA256SUMS.txt).Split()[0]
$actual = (Get-FileHash .\vaultwarden-extension-vX.Y.Z.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 checksum mismatch" }
```

No output means the checksum matches. Delete the files and do not install the
extension if PowerShell reports a mismatch.

### Google Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode** in the upper-right corner.
3. Select **Load unpacked**.
4. Select the extracted folder that directly contains `manifest.json`.
5. Pin **Vaultwarden Extension** from Chrome's Extensions menu if desired.

### Microsoft Edge

1. Open `edge://extensions`.
2. Enable **Developer mode** in the left sidebar.
3. Select **Load unpacked**.
4. Select the extracted folder that directly contains `manifest.json`.
5. Pin **Vaultwarden Extension** from Edge's Extensions menu if desired.

The browser may display a warning about extensions running in Developer mode.
That warning is expected for manually loaded, unpacked extensions.

## First-time setup

1. Open the extension and choose **Settings**, or open its **Details** page from
   the browser extension manager and select **Extension options**.
2. In **Connection**, enter the base URL of your Vaultwarden server, such as
   `https://vault.example.com`. Do not append `/api` or `/identity`.
3. Save the URL and approve the requested site access. This permission lets the
   extension contact your server and offer autofill on approved pages.
4. Open the extension popup and sign in with your Vaultwarden email address and
   master password. If the server allows registration, **Create account** can
   create a new vault directly from the login screen.
5. Complete two-factor authentication if prompted, then select **Sync** if the
   vault does not populate automatically.

The extension never submits a web form automatically. Select a credential or a
fill action to place values into detected fields.

## Update

Unpacked extensions installed from GitHub Releases do **not** update
automatically.

1. Download and verify the new release ZIP.
2. Extract it to a new temporary folder.
3. Close any open extension popup, Options page, or Receive page.
4. Replace the files in the permanent extension folder with the newly extracted
   files. Keep the folder path unchanged.
5. Open `chrome://extensions` or `edge://extensions` and select **Reload** on the
   extension card.
6. Confirm that the displayed version matches the downloaded release, then open
   the popup and sync the vault.

If the browser reports a manifest or loading error, restore the previous release
folder and reload it before troubleshooting the new package.

## Troubleshooting

**The browser cannot find `manifest.json`.**

Select the directory that directly contains `manifest.json`, not the ZIP and not
a parent folder created by an extraction tool.

**The extension disappears after moving or deleting files.**

An unpacked extension runs from the selected directory. Restore that directory
or remove the broken entry and load the extension again from a permanent folder.

**The Vaultwarden server cannot be saved or reached.**

Confirm that the URL opens in the same browser, uses the correct scheme and
port, and does not include an API suffix. Review TLS certificate errors and
approve the host-access prompt when saving the URL.

**Autofill does not appear on a site.**

Open the extension's Details page, check **Site access**, reload the website,
and confirm that the vault is unlocked. Browser-internal pages such as
`chrome://` and `edge://` do not allow extension content scripts.

**A new version still shows the old behavior.**

Verify that the permanent folder was replaced, select **Reload** on the browser
extension page, and reload any already-open website tabs.

For reproducible defects, open a GitHub issue with the extension version,
browser version, Vaultwarden server version, and sanitized reproduction steps.
Never include master passwords, session tokens, vault exports, TOTP secrets, or
real credentials.

## Remove the extension

1. Open `chrome://extensions` or `edge://extensions`.
2. Select **Remove** on **Vaultwarden Extension** and confirm.
3. Delete the extracted extension folder and any downloaded release archives.

Removing the extension deletes its browser-managed local data. It does not
delete the Vaultwarden account or server-side vault data.

## Build from source

Building from source requires Node.js 22 and npm.

```powershell
git clone https://github.com/moooyo/native-chrome-vaultwarden-extension.git
Set-Location .\native-chrome-vaultwarden-extension
npm.cmd ci
npm.cmd run build:prod
```

Load the generated `dist` directory with **Load unpacked**. Development builds
are not release artifacts and do not include a GitHub-published checksum.

## Development

```powershell
npm.cmd ci
npm.cmd run lint
npm.cmd run typecheck
npm.cmd test
npm.cmd run build:prod
npm.cmd run test:ui
```

Use `npm.cmd run watch` for incremental development builds. Live tests under
`test/live` require a separately configured Vaultwarden test environment and
are skipped by the default test command when that environment is unavailable.

`npm.cmd run test:ui` builds `dist/` and loads the unpacked extension in a real
Chromium to smoke-test that the popup, options, and receive pages render the
MiYu design with no console errors (`tools/verify-render.mjs`). `npm.cmd run
verify:e2e` additionally logs into the configured Vaultwarden test server and
checks the popup reaches the vault. Both drive the real built extension rather
than isolated component fixtures.

## Release for maintainers

Git tags are the only release trigger and source of release identity. Before
publishing `vX.Y.Z`:

1. Set the same numeric `X.Y.Z` version in `package.json` and
   `src/manifest.json`. Chrome manifest versions cannot contain prerelease
   suffixes.
2. Commit the version change and run every development command listed above.
3. Verify the exact local package:

   ```powershell
   npm.cmd run release:prepare -- --tag vX.Y.Z
   ```

4. Create and push an annotated tag that points to the verified commit:

   ```powershell
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

The Release workflow checks out the exact existing tag, installs locked
dependencies, runs lint, typecheck, tests, and the production build, creates a
root-manifest ZIP, verifies the packaged runtime files, writes
`SHA256SUMS.txt`, and publishes both assets to GitHub Releases. A tag such as
`vX.Y.Z-beta.1` becomes a GitHub prerelease while its package and manifest
versions remain `X.Y.Z`.

To rebuild assets for an existing immutable tag, run the **Release** workflow
manually and enter that tag. The workflow cannot create or move tags and rejects
all version mismatches.

## Security

Treat this extension as security-sensitive software. Install only artifacts from
this repository's GitHub Releases, verify checksums, keep the browser and
Vaultwarden server updated, and lock the vault when it is not in use.

Report suspected vulnerabilities privately through the repository's GitHub
security advisory interface when available. Do not disclose secrets or an
exploitable proof of concept in a public issue.

## License

No license file is currently included. Unless and until the repository owner
adds one, copyright law reserves reuse and redistribution rights.
