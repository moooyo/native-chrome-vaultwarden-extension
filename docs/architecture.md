# Architecture and security boundaries

MiYu is a Chromium MV3 extension. Its service worker owns authentication, vault operations,
authorization, and synchronization. Extension pages request use cases through messages or bounded
Ports. Content scripts discover fields and interact with documents; they do not own vault keys.

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| `core/crypto`, `core/api`, `core/vault`, `core/session` | Cryptography, server protocol, vault use cases, and account state |
| `platform` | Injected persistent and session storage adapters |
| `background` | Browser adapters, lifecycle coordination, and privileged message admission |
| `messaging` | Cross-context payloads, parsers, and transport limits |
| `content` | Bounded document discovery, user interaction, and target revalidation |
| `ui` | Presentation, drafts, and asynchronous client operations |

Keep browser integration out of the core. Use-case extraction must retain the shared vault mutation
coordinator and final authority checks; independent services must not invent parallel authorization
or storage rules.

## Secret response submission

Account, session, policy, vault-generation, and content-runtime authority are distinct. A locked
account may still synchronize ciphertext, while plaintext release requires an unlocked session.

The router captures a revocable runtime authority before admitting a runtime-bound request. The
coordinator observes its durable journal and binds that observation to synchronous global, tab, and
frame fences. Navigation, activation, lock cleanup, and corrupt or over-capacity journal recovery
revoke these fences before asynchronous cleanup completes.

Complete all asynchronous work and pending timeout actions before the final release checkpoint.
After the checkpoint, synchronously validate the response's original authorities and runtime fence,
consume the release proof once, and return or post the response. Do not add storage reads, cleanup,
or other awaited work after those final assertions. The proof's authority assertions suppress the
ordinary session timeout preflight; preserve that behavior rather than sampling a new wall clock.

## Authentication record writes

`auth`, `accounts`, and session-backed token records describe one account registry. Every mutation
that changes the active authentication record, including removal of an unlocked-session binding,
must own the SessionManager registry queue. Public entry points acquire the queue; helpers suffixed
`WithinRegistryMutation` require the caller to own it already. Calling a queued public operation from
such a helper can deadlock.

Token migration repairs only an exact same-credential, same-token-revision stale local copy. Unknown
record mismatches retain the existing fail-closed startup recovery behavior.

## UI session reconciliation

Routes are presentation state. A surviving Popup must read authoritative authentication state after
an external session transition, clear obsolete secrets and drafts, and then choose its next route.
Generation and request-sequence checks prevent delayed bootstrap, account-switch, or unlock replies
from replacing a newer session. Local unlock continuations remain owned by their original attempt.

## Binary file transport

Send and attachment transfers use the `vault-binary-v1` Port from exact extension-owned Popup or
Options documents. The protocol permits one active transfer and at most one unacknowledged 256 KiB
chunk. Message parsers enforce declared byte counts, sequence numbers, total size, and exact shapes.
The client reads file slices; downloads become Blob parts without building one whole-file base64
string.

Session and account ownership remain fixed for the entire transfer. Upload staging also binds the
admission policy. Once a vault use case begins, its operation guards own policy enforcement; its
final authority binder covers the result after mutation reconciliation. This allows the mutation's
own successful sync to publish a new policy generation without cancelling that same result. Policy
revocation still cancels staging and invalidates already-bound download results.

Each worker-to-client secret chunk passes a durable release checkpoint and synchronous final
assertions immediately before `postMessage`. Cancellation, disconnection, lock, and timeout clear
owned byte buffers. An in-flight server operation retains its capacity reservation until cleanup
finishes. Successful mutations are marked committed before fallible activity bookkeeping so a
withheld result reports `committed_unsynced` instead of inviting a duplicate write.

Send files retain the 100 MiB limit. Attachments retain the existing API byte budget and encryption
overhead allowance. Legacy whole-base64 methods enforce a separate 64 MiB JSON message budget,
including actual envelope bytes. They are compatibility adapters, not the large-file path.

File encryption still uses bounded whole-file buffers. Chunked browser transport does not imply
streaming encryption or remove its memory limits. Extending those limits requires a separate design.

## Derived cache work

Concurrent rebuilds with the same identity, raw generation, session binding, and authority generations
share one in-flight decryption. Each waiter performs its own final authority checks. Settled or failed
tasks are removed immediately. The 4 MiB session snapshot budget remains unchanged; sequential reads
after quota or size fallback may rebuild again. No second persistent plaintext cache is introduced.

## Verification

Follow `AGENTS.md` for the execution environment. Unit regressions exercise queue ordering, stale
runtime and session authorities, UI reply races, cache rebuild counts, and binary transport limits.
`verify:binary-transport-browser` builds an isolated test extension using production transport and
authority components, sends files through native Chrome Ports, and checks backpressure, cancellation,
lock revocation, and buffer cleanup against a synthetic backend. It does not validate a live server's
attachment or Send implementation. Existing live tests cover those server-specific use cases.
