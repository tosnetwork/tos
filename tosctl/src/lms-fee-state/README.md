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
