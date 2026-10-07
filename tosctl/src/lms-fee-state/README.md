# Shared V5R2 fee custody state

This crate compiles the existing `lms_fee_schedule.rs`, `lms_fee_journal.rs` and
its `lms_fee_cache.rs` directly. It does not fork the reservation format,
single-writer rules, restore barrier, poisoning behavior or exact retry cache.
Only the node-specific proof/transaction adapters are excluded by this crate's
private build configuration. The `contracts` crate retains those adapters.

This is a state component, not a signer or mobile readiness certificate.
Platform adapters still need authenticated route/time/counters, reviewed LMS
signing and verification, private seed custody, and expiry/consumption checks
before broadcast. Callback verification must never trust an endpoint verdict.

The journal owner explicitly releases its lock on drop. A duplicate descriptor
inherited during process creation must not postpone custody handoff. The
duplicate-descriptor regression first fails with `EWOULDBLOCK` without that
release; restoration allows reopen while retaining reservations and the
next-slot barrier. Concurrent owners remain refused.

```sh
cargo test -p lms-fee-state
cargo check -p contracts --lib
```

Host tests cover scheduling, durable ordering, real process handoff, cache
integrity, exact retries, failure poisoning and file/path constraints. Device
builds, platform FFI and complete mobile recovery remain separate acceptance
work. The ignored child probe is invoked explicitly by the process-handoff
test; it is not a skipped ownership scenario.

## Native state interface

`sdk/native/v5r2/tos_fee_state.h` exposes process-local integer session handles,
capacity previews, durable reservations and close. Sessions and pending tokens
are bounded at 256 and 1,024 respectively. Contention returns BUSY; a poisoned
registry returns INTERNAL and must not be treated as a retryable capacity hint.
Close invalidates handles/tokens while leaving reservations burned on disk.

The C interface exposes verified cache storage/read callbacks and an atomic
reservation/sign/verify/cache/export operation, but no broadcast. The atomic
operation calls the signer only after the reservation is persisted, and exports
bytes only after verification and immutable cache synchronization. Callbacks must be trusted native cryptographic primitives, never RPC
verdicts. Storage consumes a same-session token once; failed verification keeps
the leaf burned. Cache reads reverify before copying bytes to caller output.
A reservation receipt is not crypto approval. Caller-provided time
and chain counters must come from the platform's authenticated proof layer.
Rust tests and `fee-state-ffi-test.c` cover ownership, stale previews, failure
outputs and restart barriers. iOS/Android target builds are build evidence,
not on-device lifecycle acceptance.

Cache callback tests use explicit framing-only verifier doubles to prove call
ordering, token ownership and immutable retry behavior. They do not establish
LMS cryptographic correctness or platform signer integration.
