# Bounded evidence retention and the production doctor (2026-09-30)

Branch `cc/retention`, based on `node-health-monitor` at `2480a7590`.
Commits: `b8580d881` (retention in M), `fecdc67ca` (doctor, README).
Nothing on this host was deployed, restarted or reconfigured; the live
evidence database was opened read-only twice (for sizing and for the doctor
demonstration) and no token or key file was read.

## Why

The supervised M evidence database on this host held 19,847 observation
rows / 45.8 MB of body after about 2.7 hours of six-node operation
(roughly 17 MB per hour across 100 (node, scope, process_epoch,
source_epoch, source) identities). With the development quota of 256 MiB the
store fills in well under a day, after which every insert is refused and the
monitor is blind. The earlier review in `evidence/c09-retention/RETENTION-GAP-PLAN.md`
identified the two things a deletion must not break: an old replay must not
re-enter with a fresh sequence number, and Q's retained parents must stay
present. Both are addressed below; the cross-process fence that review
proposed is not implemented (see "Left open").

## Item A: what M now does

Implementation: `crates/health-services/src/retention.rs` (policy, bounds,
status, writer schedule), `EvidenceDb::retain` and the seal checks in
`durable.rs`, the seal check on the diagnostic batch path in
`diagnostic_ingest.rs`, and the writer loop, config keys and published
facts in `manager.rs`.

- `ManagerConfig.evidence_retention_ms` and `witness_retention_ms`, both
  `Option<U64>` with serde default `None` (old configs stay valid, store
  unbounded as before). `Manager::start` refuses values outside
  1 h .. 90 d before opening any database.
- The evidence writer thread now waits with `recv_timeout` and runs one pass
  every 5 minutes (first pass at thread start) plus one recovery pass after
  a write refused for space (`database or disk is full`, `WAL quota
  exceeded`, `disk I/O error`), spaced at least 30 s apart, then retries the
  refused write once. Single-writer discipline is unchanged: the pass runs on
  that thread's connection.
- A pass scans `observations` by `store_seq` in pages of 512, at most 16
  pages or 1 s, and deletes rows whose `json_extract(body,'$.record.received_at_ms')`
  is older than `now - max(window, 2 h)`. Never deleted: rows younger than
  the 2 h floor, the newest 8 rows per (node, scope, source) (a new
  `observation_source_seq` index makes that lookup an index seek), rows
  whose `source_record` has no canonical decimal generation, and any row in
  `quarantined`, `witness_quarantined`, `witness_current_activation`,
  `database_identity` or the control database. Witness rows use
  `receipt.first_received_at` (RFC 3339, parsed in Rust) with the same
  floor and newest-8 rule per endpoint. `PRAGMA wal_checkpoint(PASSIVE)`
  follows each pass; no VACUUM; `sqlite_sequence` is never reset.
- Every deletion commits, in the same transaction, a per-identity seal
  (`retention_seals` keyed on node/scope/process_epoch/source_epoch/source,
  `witness_retention_seals` keyed on observer_epoch/endpoint/source_epoch)
  holding the highest deleted generation. `insert` refuses a later record at
  or below the seal with `EVIDENCE_EXPIRED`; `insert_witness` does the same;
  a diagnostic batch record at or below the seal is acknowledged as a
  duplicate so the producer stops resending. Per-row tombstones were
  rejected on cost: at the live rate they would be about 50 MB/day; seals
  are one row per identity (100 today) and are kept for the life of the
  database.
- The state endpoint gains `retention` (configured, both windows, floor,
  period, passes, failed passes, rows deleted per table, unsealable kept,
  last pass time/age/complete/error, oldest retained receipt and its age,
  row counts), `inventory` (revision, network, node/scope/rule bindings),
  `quarantined_sources` (from the live quarantine map) and `notification`
  (receiver configured, alias, deliveries and last accepted receipt in this
  process lifetime). `/metrics` gains `tos_health_evidence_retention_configured`,
  `_passes_total`, `_failed_passes_total`, `_rows_deleted_total{table}`,
  `_last_pass_age_seconds` and `tos_health_evidence_oldest_retained_age_seconds`.

Tests (`crates/health-services/tests/retention.rs`, 10; `tests/manager_retention.rs`, 3;
two unit tests in `retention.rs`), all on real SQLite files:
old rows deleted / young kept / replay refused / sequence not reused; 2 h
floor beats a 1 h window; newest 8 per source survive any age; quarantine
and identity tables untouched; an open incident and its pending outbox in
the control DB survive a full pass; a full quota is freed by a pass and the
next insert succeeds; a row Q retained (real `read_process_projection_page`
with the retained set) is not deleted inside the floor and the projection
revalidates, and once past both bounds the projection reports
`retained M parent missing` rather than anything silent; unconfigured policy
and unsealable records delete nothing; witness archive keeps newest 8,
leaves `witness_quarantined` and the activation row alone, refuses a sealed
replay and admits a newer generation; the writer schedule recovers exactly
once per spacing after a capacity refusal and never for content refusals;
config bounds; state and metrics carry the new facts.

### Mutation checks (compiled, each reverted with `git checkout`)

1. Remove the 2 h floor (`retention_ms.max(RETENTION_FLOOR_MS)` -> `retention_ms`):
   `two_hour_floor_overrides_a_shorter_configured_retention` and
   `a_parent_the_query_service_retained_within_the_floor_is_never_deleted`
   red (the latter with the real `retained M parent missing` failure), 8 green.
2. Ignore the newest-8 protection (`floor.is_some_and(|f| row.0 < f)` ->
   always true). The replacement matched the identical guard in both the
   observation and the witness path, so both protections went at once:
   7 red (`newest_rows_per_source_survive_any_age`, the witness test with
   12 deleted instead of 4, quarantine, open-incident, quota, Q-parent and
   unsealable tests), 3 green. A first attempt that deleted the whole guard
   did not compile and proved nothing; it was redone as a condition change.
3. Disable the observation seal check (`observation_sealed` returns false for
   any generation > 0): `old_rows_go_young_rows_stay_and_a_replay_is_refused_as_expired`
   red at the `EVIDENCE_EXPIRED` assertion, 9 green.

## Item B: the doctor

`scripts/doctor.py` (tests in `tests/test_doctor.py`, 16 cases; example
receipts file `config/doctor-evidence.example.json`, all `not_run`).
Reads only: the manager state (`--manager-state-url` + `--manager-read-token-file`,
or `--manager-state-file`), the evidence DB read-only (`--evidence-db`,
`mode=ro` + `query_only`), the receipts file (`--evidence-file`). Exit 1 on
any `fail`, 2 on a usage error (unreadable/insecure token file, malformed
receipts file), 0 otherwise. `--json` for machine output, `--now` for
deterministic runs.

Receipts file schema: `{"schema_version":1,"gates":{gate_id:{status,evidence_path,at,note}}}`.
A `pass` receipt counts only with a valid RFC 3339 `at` that is not in the
future and younger than `--receipt-max-age-days` (90), and an evidence path
that exists (`--no-check-evidence-paths` relaxes that). Anything else is
`fail` (malformed, missing path, bad time) or `not_run` (absent, stale, or
declared `not_run`).

Gates: `manager_state`; `rule_inputs_usable` (inventory targets x rules
all present in `incidents` with input `good` or `bad`); `no_quarantined_sources`
(live list empty and, when the DB is given, `quarantined` and
`witness_quarantined` empty); `evidence_retention` (configured, a completed
pass within 2x `period_ms`, no `last_pass_error`); `notification_receiver`
(configured and an accepted delivery within 24 h, from the live state or a
`notification_delivery` receipt); `ai_lane` (`not_run` when `ai_unavailable`
is unbound, `fail` when bound and never evaluated or active);
`physical_separation`, `performance_round_a`..`_f`, `soak_72h`,
`token_rotation`, `cert_rotation`, `rollback_drill` from receipts. When the
state cannot be read, `manager_state` fails and the state-dependent gates are
`not_run`, so the run still exits 1.

Demonstration on this host, read-only, without a token (the live manager
predates the new state keys so its state was not fetched):

```
python scripts/doctor.py --evidence-db $HOME/nhm-supervision/c09-local/runtime/evidence/evidence.db \
    --evidence-file config/doctor-evidence.example.json
-> no_quarantined_sources pass; manager_state and the five state gates not_run;
   11 receipt gates not_run; "pass 1  fail 0  not_run 16"; exit 0
```

## Commands and results

Run from `tools/node-health-monitor/` in the `cc/retention` worktree:

```
cargo fmt --all -- --check                                              -> clean
cargo clippy --workspace --all-targets --features mcp --locked -j64 -- -D warnings   -> clean
cargo test --workspace --locked -j64 --features mcp                     -> every binary ok, 0 failed
  (new: retention 10, manager_retention 3, retention unit 2; durable 12, manager 9 still green)
<venv>/bin/python scripts/check-contracts.py                            -> PASS: 24 closed schemas ...
<venv>/bin/python -m pytest -q tests/test_doctor.py                     -> 16 passed
```

`<venv>` is the C07 contract venv in the operator's home; pytest 9.1.1 was
added to it with `uv pip install --python <venv>/bin/python pytest` because
it had jsonschema only.

## Left open

- The retention window is a time bound, not a Q-aware fence. Q revalidates
  every retained parent on each projection and blocks all manager queries
  when one is missing; the floor guarantees only two hours. The operator
  must set `evidence_retention_ms` at or above the longest time a query row
  can stay resident in Q. The cross-process fence in
  `evidence/c09-retention/RETENTION-GAP-PLAN.md` remains the complete answer
  and is not implemented here.
- Seals are kept for the life of the database (one row per identity;
  identities turn over with process and source epochs). No seal pruning.
- The 5-minute period, 2 h floor, newest-8 rule and page/time budgets are
  constants, not config.
- A full initial pass on a large backlog is bounded to 8,192 deletions per
  pass; a store far past its window drains over several periods, or faster
  under quota pressure through recovery passes.
- `notification.last_delivery_at_ms` is process-lifetime state; after a
  restart the doctor needs a receiver-side `notification_delivery` receipt
  until the next accepted delivery. On a quiet system with no incident
  transitions in 24 h this gate fails by design.
- The doctor was not run against the live state endpoint (no token read);
  the deployed manager must carry `b8580d881` for the `retention`,
  `inventory`, `quarantined_sources` and `notification` keys to exist.
- No pass was run against the live database (nothing deployed).
