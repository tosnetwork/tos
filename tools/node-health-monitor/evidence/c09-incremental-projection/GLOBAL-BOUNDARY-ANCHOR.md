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

## Mixed process/diagnostic follow-up (isolated branch)

Integration candidate `nhm/c09-global-boundary-2836` is based on shared
`2836e2bb2991d2cd559d9bbcb46bfb3027ad2bfb`, which already contains the
global-anchor implementation and typed fail-closed capacity handling. Only
the mixed-boundary control and this receipt are added; the original `f022`
base above describes the earlier implementation lineage, not this candidate.

The cursor anchor is a **global M boundary**, not a declaration that its row
is process evidence. On a partial page it is the last projected process row
and `watermark` stops there. On a fully caught-up page it becomes the exact
M observation at the global watermark, even if that row is diagnostic. The
same M read transaction supplies `boundary_witness`; Q advances only after
the process projections are committed. Process provenance is held separately
in bounded `query_origins` (original M sequence, hash, and body) and is
revalidated on restart/import. A diagnostic boundary is never inserted into
that process-parent table or promoted to a query fact.

The added `process_parent_and_trailing_diagnostic_have_distinct_durable_identities`
control inserts process seq 1 and diagnostic seq 2. It checks Q retains only
the seq-1 process origin, persists global cursor `(2, diagnostic_hash)`,
reopens successfully, then separately refuses when the M diagnostic boundary
hash changes or that boundary row is deleted. The prior process row stays
unchanged in both negatives.
The exact control passed, and the rebased `manager_query_source` target had
21 passed / 1 opt-in ignored; fmt, Clippy `-D warnings`, and diff check passed.
A compiled mutation restoring the old `source='process'` anchor lookup failed
at the expected restart assertion (`M projection anchor changed`); the source
was restored and the full targeted suite passed again.
Restored test SHA-256: `1ddff76f24f17558356255cb6b36dc63fdf13bc1bf0aec4557fc3cf7c65e682a`.

Legacy Q cursors with nonzero watermark and null anchor are refused on open;
the diagnostic-only control demonstrates this on a disposable temporary Q
database, not the local deployed ledger. They cannot silently skip a
diagnostic-only prefix. Rebuilding/migrating such a cursor needs a separate
reviewed path. This follow-up is still an isolated
development candidate, not a live Q update or a C09 soak acceptance.
