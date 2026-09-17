# Production component browser workbench

This development harness imports the current `src` implementation directly. It does not import the
HTML design atlas. It mounts the actual popup, options, and receiver root components, and the actual
closed-shadow inline surface factories.

Only the external seams are replaced: browser API access, worker requests, transfer-client responses,
receiver fetch responses, and login/generator/TOTP form mutation callbacks. Card and identity scenes
use the real detector, frame controller, field preview, staged native writes, and undo receipt; only
the returned vault values are synthetic. The production trusted-event checks,
component state transitions, validation, navigation, draft behavior, and rendering remain active.
Scenario presets open item views by dispatching the same public component events as the vault list;
editor presets then click the real edit control. They do not assign private router state or bypass
reprompt verification. All sample values are synthetic and publicly documented in the fixture UI.

## Remote build and serve

Run only in the designated verification environment unless local verification has been authorized:

```sh
node tools/build-ui-workbench.mjs
HOST=0.0.0.0 PORT=4317 node tools/ui-workbench/serve.mjs
```

Forward the remote service to the desktop for built-in browser review:

```powershell
ssh -N -L 4317:127.0.0.1:4317 test-env
```

Open `http://127.0.0.1:4317/`. The scenario rail covers authentication, the vault, typed details and
editors, reprompt, settings feedback, Send creation, data import/recovery, Send receiver email/OTP,
login/card/identity filling, generation, TOTP, and save success/uncertain outcomes. Use the reset
control to recreate a clean fixture. The failure control affects only the next fixture write and
does not clear an editor draft.

The UI includes a synthetic master password and email OTP. Receiver ciphertext is generated in
memory and decrypted by the real Send implementation. No request reaches the example server.
The import file adapter accepts a local test file and returns a deterministic preview; this tests
the production transfer UI, not format parsing. A `sample-import.json` file is emitted next to the
compiled workbench for this purpose.

## Evidence and limits

`build-metadata.json` records which production sources are in the bundle and lists replaced seams.
`window.uiWorkbench.snapshot()` exposes scenario, current route name, and request type/result only.
It never records form values or secrets. Inline iframe body data attributes record action name/count
for automation while closed roots and `Event.isTrusted` checks remain unchanged.

Card and identity presets start with an existing name. Click a candidate to inspect the production
field review, deselect the CVC or phone, and confirm. During the three-second receipt window, edit the
card number or email and click undo. The later manual edit is retained while unchanged filled fields
are restored. The remote check uses actual trusted mouse/input events, not a patched event guard.

This workbench verifies production rendering and component interaction. It is not a replacement for
an actual MV3 extension run, real browser messaging, backend integration, encryption correctness,
or permission-bound autofill tests. Those checks must remain separate and report their own scope.
