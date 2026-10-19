# C09 fail-closed lag classification follow-up

This follow-up to `LAG-VERSUS-CONFLICT-SUCCESSOR.md` corrects the error boundary
on `f0220bd7382dd00edacc386ac9ade2392bf4318d`. The previous classifier
preserved old fixed-W grants for every unrecognized Q insertion or cursor
commit error. Its positive fault tests used SQLite `RAISE(FAIL)` triggers, which
are constraint failures rather than proof of temporary storage pressure.

The corrected importer pauses only for the exact bounded refusals
`active grant evidence retention` and `M parent retention full`. It leaves the M
cursor fixed, marks catch-up false, refuses new grants, and retains existing
fixed-W grants. Every other insert error and every cursor-commit error latches
conflict and revokes active grants. In particular, unexpected SQLite, source,
metadata, and cursor errors cannot become a recoverable pause by falling
through a string blacklist. Typed, independently tested SQLite busy/full
classification remains future work; this follow-up does not claim that Q
storage faults are continuously available.

Verification on this source:

Source SHA-256: `src/observability.rs`
`bbfafbb4a148cc439b911b521c5fa086d986948c083d7880fa00e6739d8797d3`;
`tests/manager_query_source.rs`
`d32342bb158b18759c73d6fcd0e3fd95538589f9243dd46353ee8abcc1aece0d`.

- `cargo fmt --all --check`: passed.
- `cargo clippy --locked -j2 -p tos-health-services --tests -- -D warnings`: passed.
- `cargo test --locked -j2 -p tos-health-services --test manager_query_source`: 17 passed, 1 opt-in live cost test ignored.
- The actual-router trigger control checks that both mid-page insert and
  cursor-commit constraint failures revoke old grants; it also checks cursor
  replay after restart. The 4097-row active-W control reaches a real bounded
  eviction pause, keeps the old query available, refuses new grants, holds the
  cursor, and resumes after explicit grant revocation.

No running service was changed. The local QueryService still runs the reviewed
`14bb30d0` incremental binary. C09 concurrent latency, Q-aware 72-hour soak,
retention, and production acceptance remain open.
