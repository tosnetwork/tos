# C09 three-gate source reconciliation

This successor is based on the clean shared `a1a833e3a61e6f196aad22da809e6abed18b6e98`
source, but was implemented and tested only in the separate
`nhm/c09-anchor-integration` worktree. It was not deployed.

1. `M parent retention full` and `active grant evidence retention` already
   paused import without revoking an older fixed-W grant in shared `a1a833`.
   The existing >4097 test also already had a mandatory
   `assert!(paused_for_grant)` and checked old-grant usability after saturation.
   Those two reported draft gaps were stale against that exact HEAD.
2. A verified cursor/source invariant still revokes grants. This successor
   labels SQLite failures originating in `commit_manager_cursor` as
   `M cursor storage: ...`; only those failures leave the old cursor and old
   fixed-W grant intact, mark new grants uncaught/unavailable, and replay the
   committed page after the write fault is removed. Unknown and invariant
   errors continue to fail closed. The injected cursor-update trigger test
   checks old-grant HTTP 200, new-grant 503, cursor unchanged, restart/replay,
   and the surviving original grant. Its injected projection-insert case still
   verifies conflict/revocation.
3. A nonzero persisted M watermark requires a real `(store_seq, lowercase
   64-hex content_hash)` anchor. The same-snapshot page reader witnesses the
   global boundary even for diagnostic-only M history. SQL-tampering a Q
   cursor to `watermark=1, anchor=NULL` refuses startup before grant. This
   control is in the preceding global-boundary successor on this branch.

Exact relevant command `cargo test --locked -j2 -p tos-health-services --test
manager_query_source` exited 0: 18 passed, 1 explicitly ignored opt-in live
cost witness. The exact injected-failure test exited 0. A compiled mutant
that disabled only the cursor-storage branch exited 101 at the intended
`manager_conflicted` assertion (actual true, expected false, test line 794);
after restoration the exact injected-failure test and full relevant suite
returned 0. `cargo fmt --all --check`, locked `cargo clippy -p
tos-health-services --all-targets -- -D warnings`, and `git diff --check`
returned 0. No whole-package green result is claimed: an unrelated witness
fixture fixed to a role window ending 2026-09-30T00:00:00Z is red after its
expiry, as recorded in `GLOBAL-BOUNDARY-ANCHOR.md`.

Restored source SHA-256: `query_ledger.rs`
`c22ca0b983632250cb55034a6cefd6ac34bde8fbdcf009398dda528536dc6570`,
`manager_query_source.rs`
`0ebdd0f77612692f7c869c4912efa22cf1fef1e7cd5bef351fdf7eb3b0e9f8f3`,
`observability.rs`
`7a7d0303c99a76c790d494e49e1b07825d9852454ad71b86aa81fb2234a8ca66`,
`tests/manager_query_source.rs`
`0bb2bc1ea8cd2f1f7b8743315b1f54f5e4acd5ba693bc2673ff6893910a0c841`.

This is code/test closure for the three reviewed source gates, not C09
production acceptance. The measured startup catch-up and remaining per-row
`EvidenceStore` clone cost are in `STARTUP-CATCHUP-COST.md`; no limit or timeout
was increased.
