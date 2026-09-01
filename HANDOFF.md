# Engineering Handoff

Date: 2026-09-01

## Snapshot

- Working branch: `main`
- Starting commit: `5465a49` (`feat(ui): finish reachable flows and Send experience`)
- Official comparison baseline: Bitwarden Browser `v2026.8.0`, commit
  `f60a4606b7581c338d18091a98640ee71392f015`
- Primary backend target: self-hosted Vaultwarden
- Store publishing is explicitly outside this work. Releases remain unpacked GitHub artifacts.

This branch is a large parity and hardening pass. It intentionally keeps the service worker and
vault layer authoritative for secret release. Content scripts discover targets and present UI, but
they receive secrets only through short-lived, purpose-bound intents whose account, session,
document, URL, policy, and target bindings are revalidated after asynchronous work.

## Delivered

### Authentication and account lifecycle

- Master-password login, email/authenticator/FIDO2/Duo two-factor flows, remembered 2FA, SSO, device
  login approval, account passkey unlock, PIN unlock constraints, password hint, forced password
  change, and key rotation recovery.
- Session, account, server, policy, and raw-policy generation leases guard asynchronous operations.
- Security-stamp reconciliation revokes stale credentials and prevents an old sync response from
  publishing vault state after server-side revocation.
- Configurable vault timeout, idle/background/window-lock behavior, and cleanup of session-only key
  material.

### Vault and organization behavior

- CRUD for logins, secure notes, cards, identities, SSH keys, folders, collections, attachments, and
  Sends where the connected server supports the corresponding API.
- Favorites, item detail, filters, locale-aware sorting, live TOTP, password health, breach checks,
  archive/trash flows, ownership selection, and collection permission handling.
- Organization clone and mutation paths re-read raw collection grants at final authority; clone
  requires an exact current `manage=true` source grant. Organization folder metadata remains
  user-scoped.
- Account-encrypted JSON and CSV transfer paths, preview/commit separation, resumable control-plane
  state, and explicit ownership review. Vaultwarden organization import remains disabled because its
  endpoint is not atomic and may report partial cipher failures as success.

### Autofill and browser integration

- Popup, keyboard, context-menu, inline, page-load, card, identity, TOTP, custom-field, HTTP-auth,
  and registration-password generation paths use staged target revalidation.
- Form/field ownership includes document, root, form owner, composed container, and slot path.
  Right-click login targets bind `formId`, structural generation, and custom-plan digest.
- Password-shaped OTP/CVC fields, conflicting `one-time-code`/`cc-csc` hints, ambiguous forms, URL
  changes, stale reprompt continuations, and detached/reparented controls fail closed.
- Save/update capture is encrypted while unconfirmed and becomes claimable only after a narrowly
  correlated browser-owned `POST`/`PUT`/`PATCH` request succeeds. The journal stores no credentials,
  URL path/query, account identity, email, or server URL.
- Open and extension-visible closed shadow roots are discovered without patching page APIs. See the
  known interaction limitation below.
- Toolbar state has neutral, locked, and unlocked icons; pending device approvals take badge
  priority over unlocked match counts.

### Passkeys, events, and synchronization

- Website WebAuthn registration/authentication, conditional mediation, permissions-policy checks,
  iframe inventory, locked continuation, and explicit feature/host-permission gates.
- Client event production, durable queueing, acknowledgements, bounded upload, and logout cleanup.
- SignalR vault notifications, periodic sync scheduling, dirty-state coordination, and mutation
  serialization.

### Sends, generator, and release tooling

- Text/file Send create/read flows, password protection, recipient Email OTP proof for compatible
  Bitwarden cloud endpoints, endpoint/access-id binding, resend throttling, and split-origin
  permission handling. Vaultwarden currently exposes only the legacy anonymous access flow and does
  not provide recipient Email OTP challenges.
- Password/passphrase/username generation, encrypted history, enterprise generator policy, and
  server-wide history cleanup after key rotation.
- Hardened release preparation, deterministic asset verification, CI coverage, local render/E2E
  tools, and explicit repository verification rules in `AGENTS.md`.

## Deliberate Safety Differences

These are narrower than the official client by design and should not be relaxed without a threat
model and adversarial tests.

- No network-first reverse scan of password fields. A trusted submit, submit-button click, or Enter
  capture must exist before network success can confirm a save prompt. Some blur-triggered or
  automatic-fetch login flows therefore do not prompt.
- Page-load fill is top-frame, single-candidate, explicit-current-password, and non-reprompt only.
- A successful navigation may correlate network evidence across a same-site redirect, but the UI
  claim remains exact-origin.
- HTTP auth scope and custom-field regex/span behavior are conservative.
- Passkey requests requiring unsupported or unprovable user verification stay with the browser/OS;
  the extension does not copy an unsafe user-verification bypass.
- Phishing-blocker and related-origin behavior remain feature/entitlement gated instead of being
  enabled against a self-hosted server without a trustworthy data source.

## Confirmed Follow-up Work

The following findings were independently rechecked during final review. They were not rushed into
the branch after the handoff/push request because each crosses a security or performance boundary.

### P1: BFCache incarnation fencing

Persisted page restore can reuse the browser `documentId`, frame form ids, and structural generation.
An in-flight pre-restore login/structured commit can therefore collide with a fresh content runtime.
The save-capture discard is also not an atomic barrier: an older router handler or delayed
`webRequest` observation can land after cleanup, and cleanup failure currently restarts capture.

Recommended design:

1. Generate a high-entropy content-runtime incarnation on every start/resume.
2. Bind it through frame inspection, targets, intents, commits, `awaitFocus`, capture, and discard.
3. Persist a bounded retired-incarnation tombstone in the save coordinator; move
   `putUnconfirmed()` inside the serialized fence check.
4. Retire the old incarnation and clear its unconfirmed capture, username stage, request, and
   outcome metadata atomically. Preserve already confirmed captures.
5. Fence browser events that entered before `webNavigation.getFrame()` completed, or block that
   document's evidence for the full network TTL.
6. Resume capture only after an explicit successful cleanup response.

### P1: Save-capture correlation completion barrier

`onBeforeRequest` performs asynchronous `webNavigation.getFrame()` work in independent request
lanes. A fast candidate request can be journaled and confirmed after the correlation window while a
second in-window candidate is still waiting for frame resolution. Confirmation must wait until every
browser event that entered the window has either resolved or expired; otherwise an ambiguous
formless submission can be treated as unique.

The same follow-up should cover two adjacent lifecycle cases:

- Chrome may emit a second `onBeforeRequest` with the same request id after a method-preserving
  307/308 redirect. Treat that as the known redirect continuation instead of request-id reuse.
- A non-secret wake sent after the source document is replaced may receive `action: none`. Do not
  acknowledge that as a displayed prompt or remove its journal-owned expiry alarm. Pending encrypted
  credentials need an independent durable expiry/cleanup path even after a successful UI wake.

### P1: Closed-shadow interaction listeners

Discovery sees Chrome's extension-visible closed roots, but `focusin`, `contextmenu`, and
`pointerdown` are currently handled only at `Document`. Outside a closed root, `composedPath()` hides
the internal control, so inline focus/right-click can miss the field and click-away can misclassify
the interaction. Bind listeners through `AutofillDocumentController.bindRoots()` and deduplicate
events while preserving capture-phase resistance to page `stopPropagation()`.

### P1: Accessible labels and DOM scan cost

- Screen-reader-only labels use visually hidden CSS by design. Semantic-label validation currently
  applies field interactability rules and may mark these labels unsafe, excluding otherwise valid
  password/card/identity fields. Add a separate accessibility-source visibility rule that rejects
  semantic-tree removal but permits standard off-screen/clipped label text.
- Dynamic pages can trigger repeated full composed-tree scans, each visiting up to 100,000 elements
  and probing the privileged closed-root API. Maintain known hosts/roots incrementally from added
  nodes, then use an idle, bounded, backed-off sweep only for late shadow attachment.

### P2: Classification and enumeration bounds

- Non-semantic card/identity hints and multiple recognized autocomplete roles still select the first
  pattern in some cases. Collect normalized candidate roles and fill only when exactly one remains.
- The composed-tree element budget does not bound later `querySelectorAll()` field enumeration.
  Share control/count/byte budgets with detection, and fail the entire projection closed when a
  snapshot is truncated or any budget is exceeded.
- `autofill.awaitFocus` must be owned and cancelled by its runtime incarnation as part of the BFCache
  fix.
- Temporary Receive-page host permissions are tracked and retried three times in the current page
  lifecycle. A final repeated removal failure is not persisted across page destruction; add a small
  durable cleanup journal if cross-lifecycle recovery is required.

## Remaining Official-Client Capability Gaps

These are product/backend gaps rather than regressions in the implemented paths.

- True multi-account operation with independent unlock/timeout state, immutable server/user identity,
  and non-active-account notification processing.
- WebPush notification support; the current self-host target uses SignalR.
- Top-frame overlay coordination for subframe inline UI and broad split-field payment/identity forms
  such as Stripe-hosted multi-frame fields.
- Official provider-specific importers (1PUX, KDBX, XML, and other proprietary formats), forwarded
  email alias providers, account device management, and fingerprint phrase UI.
- Streaming attachment/Send transfer at the official client's larger limits. Current bounded
  in-memory paths intentionally use lower limits and must not be raised without streaming.
- Partial organization edits that preserve inaccessible encrypted fields, SSH-key cloning, and a
  broader encrypted-key/ECDSA import surface.
- Native-messaging biometric/shared unlock, which requires a separately installed and allowlisted
  native host.
- Bitwarden cloud enterprise features such as Access Intelligence, security tasks, Trusted Device
  Encryption, Key Connector, and JIT provisioning. Stock Vaultwarden does not implement several of
  the required endpoints or item types.
- Full browser matrix, mobile/Safari support, side-panel parity, complete localization breadth, and
  browser-store distribution.

## Verification Status

Focused suites for the individual changes passed during implementation, including save-capture,
toolbar, security-stamp, organization permission, Send access, field detection, and BFCache teardown
tests. The final local repository-wide verification completed successfully:

```powershell
npm run typecheck
npm run lint
npm test
npm run build:prod
git diff --check
```

- TypeScript: passed
- ESLint: passed
- Unit tests: 292 files, 7,149 tests passed
- Production build and `assert-build`: passed
- Whitespace check: passed; Git emitted only the existing Windows LF/CRLF conversion warnings

Live Vaultwarden and authenticated Chrome verification require the `test-env` backend. On
2026-09-01, `ssh -o BatchMode=yes -o ConnectTimeout=10 test-env "echo test-env-ok"` timed out, so no
final live/backend or authenticated-browser claim should be inferred from the local unit/build
results. Do not substitute a local backend containing different data.

## Recommended Next Order

1. Implement and adversarially test the BFCache incarnation/fence design.
2. Complete root-local closed-shadow event handling.
3. Separate accessible-label visibility from field interactability.
4. Make composed-tree discovery incremental and enforce a shared field budget.
5. Restore `test-env`, seed disposable data, and run live plus real-Chrome verification.
6. Address product gaps only after the security/performance follow-ups above are closed.
