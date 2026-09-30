# C09 global M boundary anchor (isolated successor)

Base: `f0220bd7382dd00edacc386ac9ade2392bf4318d`; worktree
`/home/tomi/tos-node-health-c09-anchor`. No running service was changed.

The persisted Q cursor now requires an anchor for every nonzero global M
watermark. A caught-up page anchors the exact M row at that watermark, including
when it is a diagnostic rather than a process row. The page reader obtains the
hash under its M read transaction; Q commits that boundary only with the page's
witness. Previous anchors are checked by indexed M `store_seq` lookup. A page
that is not caught up still anchors its last projected process parent.

Controls (run 2026-09-30 UTC, `CARGO_TARGET_DIR=/home/tomi/nhm-c09-anchor-build`):

- `cargo test --locked -j2 -p tos-health-services --test manager_query_source`:
  17 passed, 1 ignored before the added case; restored complete run later had
  18 passed, 1 ignored. The added test checks a diagnostic-only M snapshot,
  durable Q cursor, and SQL-tampered `watermark=1, anchor=NULL` refusal during
  QueryService startup, before any grant can be issued.
- Changed-property mutation: removed only the
  `(cursor.watermark == 0) != cursor.anchor.is_none()` condition. The exact
  added test compiled and exited 101 at its startup-refusal assertion
  (`manager_query_source.rs:192`, `Option::unwrap()` on `None`), not a compile
  or setup failure. The condition was restored; the exact test exited 0.
- `cargo clippy --locked -j2 -p tos-health-services --all-targets -- -D warnings`:
  exit 0. `cargo fmt --all --check` and `git diff --check`: exit 0.
- Full `cargo test --locked -j2 -p tos-health-services`: exit 101 on an
  unrelated date-bound `witness_archive` fixture; its role `valid_until` is
  `2026-09-30T00:00:00Z`, while the test ran after that instant. A targeted
  rerun of `synthetic_valid_clock_current_route_qualifies_context_without_proof`
  also exited 101 (`unknown` instead of `qualified`). The C09 projection suite
  in that full run was 18 passed, 1 ignored. This is **not** a whole-package
  green claim.

Restored source SHA-256:

- `query_ledger.rs`: `3b41bf7adb7131ef122af8b53949d8961f6886a311006ba7097fb6a96a995dfe`
- `manager_query_source.rs`: `0ebdd0f77612692f7c869c4912efa22cf1fef1e7cd5bef351fdf7eb3b0e9f8f3`
- `observability.rs`: `8fbca38c0c4ab7c08c2e43804a0dad9b95b5a72323a1e1fab642ca80a866e9de`
- `tests/manager_query_source.rs`: `76bf6f8608aee0d61639e49de607bc11aa4151ebf9fccfdd718980ed578b8edc`

This controls the development projection cursor; it does not establish C09
production or 72-hour availability, and it was not deployed.
