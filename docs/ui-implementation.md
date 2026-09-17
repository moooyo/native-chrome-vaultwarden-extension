# Final UI implementation

The production Lit components now use the approved blue-and-white design direction. The locally
generated review atlas is stored at `ui-final/index.html`. The development workbench renders the
production components with explicitly synthetic service adapters for browser review.

## Product surfaces

- The action popup retains definite browser-popup dimensions. Its new workspace action opens
  `ui/popup/popup.html?workspace=1`, using the same request owner and route state with a full-page
  navigation rail and separate vault list/detail panes.
- Shared controls use Instrument Sans and JetBrains Mono, a blue-gray palette, explicit focus
  treatment, compact corners, and reduced-motion support. Content surfaces register the same bundled
  fonts and maintain their own isolated theme.
- Login, unlock, trusted device approval, Passkey approval, protected items, and account maintenance
  retain account/server identity at the decision. Display metadata never grants authorization.
- Login, card, identity, secure-note, and SSH editors disclose advanced fields while preserving one
  draft and a persistent save boundary. Destructive confirmations identify their item and owner.
- Settings expose real pending, saved, and failed outcomes next to their controls. Their effective
  values update from confirmed requests; queued saves retain their existing concurrency rules.
- Sharing separates content, protection, and expiry. Receiver pages retain context through password,
  email verification, download, and retry. Import outcomes use authoritative counts and preserve
  unknown recovery work without claiming unavailable per-item backend reconciliation.
- In-page card and identity suggestions include a selected-field review. Existing values are
  excluded by default. The one-use authorization binds the canonical selected-role subset to the
  original complete form target; the worker projects only the required data, and content checks
  both field mapping and reviewed values again before writing.
- Structured-fill undo retains values only in an expiring isolated-world receipt. It rechecks
  document, form, role mapping, ownership, and the exact write value, preserving later edits.
  Successful save acknowledgements close automatically after three seconds.

## Verification entry points

Follow `AGENTS.md`: compile, lint, run unit tests, and execute Chromium extension checks on
`ssh test-env`. Built-in browser checks in this task were explicitly authorized by the user.

```sh
npm run typecheck
npm run lint
npm test -- --maxWorkers=4
npm run build:prod
xvfb-run -a node tools/verify-render.mjs
xvfb-run -a node tools/verify-autofill-browser.mjs
node tools/build-ui-workbench.mjs
HOST=127.0.0.1 PORT=4317 node tools/ui-workbench/serve.mjs
node tools/verify-final-ui.mjs
```

The workbench is available through an SSH loopback forward at `http://127.0.0.1:4317/`. Its scenario
labels and service-boundary notice distinguish fixture data from real accounts. It is not part of
the production build. Browser results and screenshots are written under `test-results/final-ui/`.

The built-in browser checks cover visible production component interactions. Separate Chromium
checks load the packaged MV3 extension. Neither fixture-based component checks nor unauthenticated
extension startup checks claim a live authenticated Vaultwarden end-to-end result.

## Recorded result

The final run passed type checking, lint, the production build gate, all 302 unit-test files
(7,648 tests passed; one existing test skipped), 42 component-browser checks, four MV3 entry-point
startup checks, and the autofill browser hardening gate. Manual in-app browser checks covered
vault/detail selection, protected company-card identity, field selection, and failed-save recovery.
The local evidence is stored in `../test-results/final-ui/verification-summary.json` and
`../test-results/final-ui/report.json`. Generated atlases, screenshots, reports, and build packages
are local review artifacts and are not included in the source commit. The commands above reproduce
the automated checks and browser report from a fresh checkout.
