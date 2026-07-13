# MiYu autofill & passkey test page

A local page that exercises every autofill surface the extension exposes — **including
passkey register + authenticate**, which the earlier test page did not cover.

## Run it

```bash
npm run serve:testpage          # serves http://localhost:8770/
# or choose a port:
npm run serve:testpage -- 9000  # → http://localhost:9000/
```

Open the printed **`http://localhost:PORT`** URL in the browser that has the unpacked
extension loaded.

> **Use the `localhost` name, not `127.0.0.1`.** MiYu validates the passkey `rpId`
> against the Public Suffix List and accepts `localhost` but rejects a bare IP as a
> non-registrable domain (`src/core/vault/domain.ts` → `isRegistrableRpId`). An IP host
> makes the passkey section fall through to the native authenticator.

### Why a server (not `file://`)

- The content scripts only match `http://*/*` and `https://*/*` (`src/manifest.json`), so
  a `file://` page gets **no** autofill and **no** passkey interception.
- Passkey `create()` / `get()` require a **secure context**. `http://localhost` counts as
  secure, so serving locally satisfies both constraints at once.

The page shows an environment banner up top and refuses to pretend things work when the
origin is wrong.

## Before you start

1. Load the extension unpacked and **unlock the vault** (open the popup, sign in). Autofill
   and passkey storage both need the unlocked vault in the background worker.
2. For the **2FA** section to show a code, your vault needs a login item whose URI matches
   `localhost` (e.g. `http://localhost:8770`) **and** that carries a TOTP secret.

## What each section tests

| # | Section | How to trigger | Expected |
|---|---------|----------------|----------|
| 1 | Login (single step) | **Focus** username or password | Side match-panel opens to the right; picking an item fills both fields |
| 2 | Two-step login | **Focus** the email field | Panel offers a username for the first step |
| 3 | Two-factor code | **Focus** the code field | Live TOTP panel for the top matching login (needs a matching login with TOTP) |
| 4 | Registration | **Focus** *Create password* | Inline generator panel; can fill + save the new login |
| 5 | Credit card | Click the **密屿** trigger under a field, right-click → 密屿, or `Ctrl+Shift+F` | Card picker → fills name/number/exp/cvc |
| 6 | Identity & address | Same triggers as card | Identity picker → fills name/address/contact || 7 | Hint-only fallback | Same triggers | Card + identity detected with **no** `autocomplete` tokens (regex classifier) |
| 8 | **Passkey** | Buttons in the section | See below |

### Section 8 — passkey (the new part)

Order matters:

1. **① Register · `create()`** — approve the MiYu consent dialog and choose which login to
   attach the passkey to (or create a new one). Stores an ES256 passkey in the vault.
2. **② Authenticate · `get()`** — approve the consent dialog; MiYu signs an assertion.

The result panel is labelled:

- **`handled by MiYu`** (green) — the returned credential is MiYu's duck-typed object, not
  a real `PublicKeyCredential`. This is the signal that the extension handled the ceremony.
- **`native authenticator`** (amber) — it fell through to the browser/OS. Usually means the
  vault was locked, the origin wasn't `localhost`, or you cancelled the MiYu dialog.

Options:

- **require user verification (UV)** — sends `userVerification: 'required'`; the UV flag in
  the returned `authenticatorData` reflects it.
- **get(): restrict to last-created id** — puts the just-registered credential id in
  `allowCredentials` to test the non-discoverable path (otherwise `get()` runs discoverable
  with an empty allow-list).

The decoded `clientDataJSON`, `authenticatorData` flags (UP/UV/BE/BS), signature and user
handle are shown so you can confirm the challenge/origin binding.

## Live detection indicators

Each section has a status chip and there's an event log at the bottom. The page watches for
the `data-vw-*` attributes the content script writes on detected fields and the
`data-vw-popover-for` panel hosts it mounts — so a chip turning **green (field detected)** or
**accent (panel open)** is direct proof the extension engaged, without any extension
cooperation. If nothing lights up, the top banner and log will say why.
