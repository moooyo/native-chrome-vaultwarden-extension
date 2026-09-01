# Engineering Handoff

Date: 2026-09-02

## Snapshot

- Working branch: `main`
- Continuation base commit: `782dfdef7982571191ec53a849eb0644522c64ee`
  (`feat: expand secure browser parity`)
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
- Open and extension-visible closed shadow roots are discovered and receive trusted capture-phase
  interaction listeners without patching page APIs.
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

## Completed Follow-up Work

The security and performance findings from the previous handoff are now implemented and covered by
adversarial tests.

### BFCache and runtime incarnation fencing

- Every content runtime receives a canonical lowercase UUID v4 incarnation and activates against the
  browser-authoritative frame document before any autofill work begins.
- Runtime identity is bound through frame inspection, popup/keyboard/context-menu/manual targets,
  intents, direct and continued commits, focus waits, save capture, and content commands.
- Replaced runtimes are retired through bounded durable tombstones. Unconfirmed captures, username
  stages, request/outcome metadata, and runtime-owned continuations are fenced or cleared without
  deleting already confirmed captures.
- Top-frame BFCache activation revokes stale child-frame content authority while ordinary navigation
  preserves the network evidence required to confirm a legitimate cross-document form submission.
- Login and structured staged fills re-run authoritative composed-tree discovery after every write,
  verify runtime ownership, and reject a changed custom-plan digest before releasing credentials.

### Save-capture completion and wake semantics

- `onBeforeRequest` installs a synchronous, durable admission barrier before asynchronous
  `webNavigation.getFrame()` resolution. In-flight capture staging also registers bounded frame
  interest before its first await, so an early competing request cannot evade the barrier.
- Confirmation fences are scoped to relevant capture windows and request ids, rechecked after every
  asynchronous persistence step, and rolled back inside the pending-store queue if authority changes.
- Method-preserving 307/308 redirect continuations are accepted exactly once; malformed reuse,
  mismatched URL/method/document bindings, and terminal parse failures remain fail closed.
- Save wakes claim the exact capture id and distinguish `displayed`, `not_displayed`, and `not_ready`.
  Only a real current-runtime surface acknowledges display.
- Pending encrypted captures have an independent durable expiry alarm. Username staging and tab/global
  cleanup now share the coordinator lane, preventing cleared secret state from being written back by
  an older queued operation.

### Closed shadow roots, accessibility, and bounded detection

- Trusted `focusin`, `contextmenu`, and `pointerdown` listeners are bound to every discovered root in
  the capture phase. Closed-root and document observations are identity-deduplicated while preserving
  the deepest trusted target.
- Accessibility-source visibility permits standard off-screen, clipped, and transparent screen-reader
  labels while rejecting semantic-tree removal.
- Composed-tree maintenance is incremental for added/removed subtrees. Late shadow attachment uses
  bounded idle slices with backoff, canonical breadth-first ordering, root cleanup, and truncation
  fences.
- Login/card/identity/TOTP/generator/custom-field detection shares bounded control, element, form,
  candidate-group, hint-byte, semantic-source, semantic-node, and custom-target budgets. Raw and final
  structured-form passes reuse identity-deduplicated candidate accounting, and any overflow invalidates
  the entire projection.
- Ambiguous autocomplete and heuristic roles no longer use first-match classification; a field is
  accepted only when exactly one normalized role remains.

One previously documented optional item remains unchanged: Receive-page temporary host-permission
cleanup retries are bounded within the page lifecycle but do not yet use a cross-lifecycle durable
cleanup journal.

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

All verification for this continuation ran on `test-env`; no local test, build, smoke, or runtime
probe was used. A checksum-verified temporary Node `v22.23.2` runtime was used to match CI's Node 22
major version.

```powershell
npm ci
npm run typecheck
npm run lint
npm test
npm run build:prod
dbus-run-session -- xvfb-run -a npm run verify:render
git diff --check
```

- Dependency install/audit: passed; 0 vulnerabilities
- TypeScript: passed
- ESLint: passed
- Unit tests: 294 files, 7,344 tests passed; 1 existing test skipped
- Production build and `assert-build`: passed
- Chrome for Testing `149.0.7827.55` MV3 render smoke: passed for popup, options, and receive pages;
  zero page/console errors. An expected background warning was emitted because no device-login server
  was configured.
- Whitespace check: passed after normalizing the Windows working-copy line endings in the disposable
  Linux verification clone.

Authenticated live Vaultwarden verification remains environmentally blocked. The service currently
published at `test-env` `127.0.0.1:18082` is `ghcr.io/bitwarden/lite`, not Vaultwarden; the unrelated
`/opt/vaultwarden/data` directory is not mounted by that container. No live test was run against this
substitute and no Vaultwarden compatibility claim should be inferred. Restore a disposable
Vaultwarden instance before running the repository's mutating live/API or authenticated browser gates.

Store publishing was not performed.

## Recommended Next Order

1. Restore a real disposable Vaultwarden service on `test-env`, confirm its container/image and data
   isolation, then run the authenticated live/API gates with cleanup enabled.
2. Add dedicated CDP-driven real-Chrome scenarios for BFCache restore, 307/308 save correlation, and
   closed-shadow interactions if those behaviors require a browser-level release gate beyond the
   adversarial unit coverage.
3. Add a durable Receive-page permission-cleanup journal only if cross-lifecycle retry is required.
4. Address the remaining official-client product/backend gaps independently of this completed
   hardening pass.
