# MiYu autofill & passkey test page

A local page that exercises MiYu's login, TOTP, generator, card, and identity field flows, plus
**passkey register + authenticate**.

## Run it

```bash
npm run serve:testpage          # serves http://localhost:8770/
# or choose a port:
npm run serve:testpage -- 9000  # → http://localhost:9000/
```

Open the printed **`http://localhost:PORT`** URL in the browser that has the unpacked
extension loaded. `http://127.0.0.1:PORT` is also supported; the server prints `localhost`
only to keep one canonical test origin.

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
2. In **Settings → Autofill**, enable **Website passkeys** and approve the browser's website
   access prompt. The feature is off by default and does not replace WebAuthn while disabled.
3. To test the on-page login, TOTP, card, and identity pickers, enable **Inline suggestions** in
   the same section.
4. For the **2FA** section to show a code, your vault needs a login item whose URI matches the test
   origin (for example, `http://localhost:8770`) **and** that carries a TOTP secret.

## What each section tests

| # | Section | How to trigger | Expected |
|---|---------|----------------|----------|
| 1 | Login (single step) | **Focus** username or password | Side match-panel opens to the right; picking an item fills both fields |
| 2 | Two-step login | **Focus** the email field | Panel offers a username for the first step |
| 3 | Two-factor code | **Focus** the code field | Live TOTP panel for the top matching login (needs a matching login with TOTP) |
| 4 | Registration | **Focus** *Create password*, then choose **Use** | Fills the password and confirmation fields; submitting the website form then triggers the normal save prompt |
| 5 | Credit card | Focus a recognized field with inline suggestions enabled, right-click → 密屿, or use the focused-fill shortcut | Card picker → fills name/number/exp/cvc |
| 6 | Identity & address | Same triggers as card | Identity picker → fills name/address/contact |
| 7 | Hint-only fallback | Same triggers | Card + identity detected with **no** `autocomplete` tokens (regex classifier) |
| 8 | **Passkey** | Buttons in the section | See below |

### Section 8 — passkey (the new part)

Order matters:

1. **① Register · `create()`** — approve the MiYu consent dialog and choose which login to
   attach the passkey to (or create a new one). Stores an ES256 passkey in the vault.
2. **② Authenticate · `get()`** — approve the consent dialog; MiYu signs an assertion.

The returned value keeps the browser's `PublicKeyCredential` prototype, so
`instanceof PublicKeyCredential` cannot tell whether MiYu or the native authenticator handled a ceremony.
The page therefore reports only the credential data it received. The visible MiYu approval UI is
the reliable manual signal that the extension handled the request.

Options:

- **require user verification (UV)** — sends `userVerification: 'required'`. MiYu currently
  leaves these requests to the browser/OS authenticator, so keep this unchecked when testing MiYu.
- **get(): restrict to last-created id** — puts the just-registered credential id in
  `allowCredentials` to test the non-discoverable path (otherwise `get()` runs discoverable
  with an empty allow-list).

The decoded `clientDataJSON`, `authenticatorData` flags (UP/UV/BE/BS), signature and user
handle are shown so you can confirm the challenge/origin binding.

## Live detection indicators

Autofill sections 1–7 have status chips and there's an event log at the bottom. The page watches for
the `data-vw-*` attributes the content script writes on detected fields and the
`data-vw-popover-for` panel hosts it mounts — so a chip turning **green (field detected)** or
**accent (panel open)** is direct proof the extension engaged, without any extension
cooperation. If nothing lights up, the top banner and log will say why.
