# Independent C09 QueryService anchor review

Read-only review of `/home/tomi/tos-node-health-c09-anchor-integration` at
`23f70487e4b84c6ff92ca60d883ce3d9b5ecff1f` plus its uncommitted WIP.
The inspected `observability.rs` SHA-256 was
`8cb02508aaf6d63fe5a6da9946d53c6a4ff6abc8888d68119965c92b8b2d0199`;
`manager_query_source.rs` was
`b31218e1d6b25a670d8eb75942631d48efbfad4de0a25328cb45689da7438f58`.
The candidate tree had modified `observability.rs` and
`tests/manager_query_source.rs`, plus untracked live-concurrent evidence.
No file in that tree or any service was changed by this review. No heavy build
or test was run against the WIP.

## Findings

1. **The current global change witness is sound as a refusal signal but noisy
   for grant availability.** `manager_data_version` uses one stable read-only
   SQLite connection (`observability.rs:168-179`), so external commits advance
   `PRAGMA data_version`. `import_manager` compares versions before/after the
   retained-parent/page read (`:209-286`); `grant` requires the last validated
   version (`:484-488`) and then the exact global M head (`:490-505`). Normal
   process inserts can invalidate both gates, with no quarantine. The bounded
   live observation below saw 14 version advances and 39 head advances in
   30 seconds while quarantine remained empty. This does **not** prove a
   deployed candidate failure rate; it makes an exact-head, 15-second refresh
   profile an availability risk requiring a live grant cadence control.
2. **Same-W quarantine is rejected for new grants after detection, but active
   fixed-W grants have a detection window.** The M page read checks each
   retained parent and quarantine in one snapshot
   (`manager_query_source.rs:239-298`). If quarantine commits after that read,
   `version_before != version_after` only sets `manager_caught_up=false`
   (`observability.rs:278-286`). The cached query route checks
   `manager_conflicted`, not `manager_caught_up` (`:588-591`), so a still-active
   grant can read its old derived parent until another import sees quarantine
   and revokes it. A quarantine commit after the one grant version check and
   before ledger creation is also a cross-database TOCTOU window. Specify and
   test the intended detection bound; do not claim instantaneous revocation.
3. **A grant can still block after its non-waiting ledger check.** It uses
   `query_ledger.try_lock()` for the cursor (`observability.rs:490-498`), then
   `query_ledger.lock()` for `create` while holding `Data` (`:524-529`). A
   concurrent importer can take ledger between these calls. Use a second
   `try_lock` for create and return 503 on contention; while Data is held, the
   importer cannot advance the cursor through its publication phase. Add a
   deterministic barrier test that holds ledger after the first check and
   verifies bounded 503, natural completion and no partial grant.

## Cheap integrity witness proposal

Do not replace `data_version` with `COUNT(*)` or `MAX(rowid)` of
`quarantined`: same-count update/delete/replacement can preserve those values.
The production M writers currently use `INSERT OR IGNORE` for quarantine
(`durable.rs:482`, `diagnostic_ingest.rs:156`), but the candidate also claims
retained-parent truth under replacement. A precise low-cost successor is a
durable singleton `integrity_revision`, incremented transactionally by
SQLite triggers on `quarantined` INSERT/UPDATE/DELETE and `observations`
UPDATE/DELETE. Ordinary observation INSERT does not advance it. Abort rather
than wrap the revision. Read the revision in the same M snapshot that verifies
retained parent seq/hash/body and the page; commit the validated value with
Q's cursor. A grant reads one revision and DB identity, then requires an exact
match or returns 503. Missing revision, schema mismatch, read error or
replacement is unavailable/conflict, never a zero/default match. Keep the
existing global `data_version` refusal until the new witness and its migration
are verified; the revision alone does not solve exact-head availability or
instantaneous cross-database invalidation of active grants.

Required controls: normal INSERT advances head but not integrity revision;
same-W quarantine INSERT changes revision and denies; duplicate ignored
quarantine does not change it; quarantine UPDATE/DELETE and retained parent
UPDATE/DELETE deny; rollback does not publish revision; overflow and DB
replacement fail closed. Hold a barrier at M validation, revision read and
grant creation to expose both quarantine races. Confirm the active-grant
contract separately from new-grant refusal.

## Bounded read-only live witness

One stable `mode=ro`, `query_only=ON` SQLite connection sampled the live M DB
31 times at one-second intervals. Each sample read only `PRAGMA data_version`,
`MAX(store_seq)` and `COUNT(*),MAX(rowid)` from `quarantined`; SQLite timeout
was 100 ms. The raw file is `live-data-version-31.jsonl`, SHA-256
`1f92bbb70a876bb820833505397f29e7bc1e7c4fa67f9e51dc906a65d0de0a25`.
It contains 31 rows, zero errors, versions 2 through 16, head 24045 through
24084, quarantine signature `(0,NULL)` throughout, and maximum combined
query time 0.415 ms. The observation is a narrow source-change cadence
witness, not a grant/SDK benchmark or a test of the new candidate binary.

Exact read command was a `python3` script opening
`file:/home/tomi/nhm-supervision/c09-local/runtime/evidence/evidence.db?mode=ro`,
executing `PRAGMA query_only=ON`, then the three SQL reads above in one loop
of 31 iterations with `time.sleep(1)` between iterations, writing canonical
JSONL under this branch. No tokens, payload bodies or node RPC were read.

Direct messages containing these findings were queued to Lighthouse thread
`01a0ebc3-945c-7b13-9794-2bd7a1588cd0` as
`01a0effc-daaf-7ff1-addb-a9f268c53fef` and
`01a0effd-4056-7071-880c-2c27d984a9ed`.
