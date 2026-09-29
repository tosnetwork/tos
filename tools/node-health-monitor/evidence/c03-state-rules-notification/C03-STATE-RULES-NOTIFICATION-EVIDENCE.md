# C03 state, rules and notification candidate

Base: accepted basic-only C02 `a884b0ca735736fd5a81306c26bdc65a5bd967df`.
This is a C03 review candidate, not production/deployment acceptance. No business
node, validator key, consensus path, main merge, C04 or C05 adapter was changed.

## Delivered boundary

- The evidence and control SQLite owners remain separate bounded writers with
  verified WAL/FULL and bounded PASSIVE checkpoint. Immutable evidence commits
  precede control `source_state` references. Whole rule round, incident,
  evaluation sequence and outbox transitions share a control transaction;
  quota/outbox failures cannot publish a green state or advance the sequence.
- The bounded snapshot route archives a validated C02 edge wire as immutable
  evidence and returns only committed references. It is **not** a rule-fact
  adapter. The 16 KiB facts route remains capped independently; the archive
  route is 256 KiB, with smaller per-record archival limits and explicit
  refusal. A partial archive failure returns no accepted receipt; replay
  deduplicates committed rows without changing their original times.
- Outbox rows now retain payload hash, approved receiver alias once bound at
  first attempt, attempt count and next due time. A C02-era pending row is
  migrated without deletion or acknowledgement. Retries space at 15/30/60
  seconds, with a stable key; only a matching accepted receipt deletes the row.
  An unconfigured row has no approved destination and cannot be delivered.
- Source availability/coverage is not promoted to complete by the collector.
  The O webhook accepts only its approved monitor and current process epoch,
  with strictly advancing sequence; an epoch change and webhook update are
  synchronized. O uses separate credentials and sends JSON with an idempotency
  key/hash directly to a test receiver. Receiver acceptance is not proof of
  end-user receipt.
- `contracts/rule-manifest.json` inventories 18 R4 rules and explicitly marks
  unimplemented C04/C05/C08 source adapters pending. The live M gate permits
  only `target_unreachable`/edge probe, `telemetry_unavailable`/inventory and
  isolated native-PQ `pq_signing_failure`; the last has no production fixture.
  Three Prometheus rules cover persisted active-incident series, M's committed
  evaluation sequence for O, and M scrape `up`/absence. Eighteen catalog rows
  do **not** mean 18 live alerts.

## Exact restored checks

- `CARGO_TARGET_DIR=/home/tomi/nhm-c03-build CARGO_BUILD_JOBS=2
  scripts/run-contract-tests.sh`: natural exit 0 in
  `raw/final-contract-workspace-restored.log`. It checks 20 closed schemas,
  six actual handler successes, the genuine 11-gate production doctor refusal
  and 121 workspace tests. The four targeted entrypoint executions precede
  the workspace count and are not added to 121.
- `cargo fmt --all -- --check`: exit 0 (`raw/final-fmt.log`).
  `cargo clippy --workspace --all-targets --locked -- -D warnings`: exit 0
  (`raw/final-clippy-restored.log`). The earlier Clippy large-enum warning and
  its failed log remain historical; boxing the queued evidence row fixed it.
- Pinned Prometheus 3.9.1 `promtool check rules` (three rules) and `promtool
  test rules` (missing/stale/reset/target removal fixtures), and Alertmanager
  0.34.1 `amtool check-config`: all exit 0 (`raw/final-tool-checks.log`).
  Archive SHA-256: Prometheus
  `86a6999dd6aacbd994acde93c77cfa314d4be1c8e7b7c58f444355c77b32c584`;
  Alertmanager
  `265b9d1e55ef0d5306a436018af6d2b686c2ce051f03d968f7464ecb1372a7e8`.
  `deploy/prometheus/runtime-flags.json` freezes the operational Prometheus
  `--rules.alert.resend-delay=15s` and AM 0/15/30-second route. Both tools
  remain `enabled=false` in the dependency lock.
- Five changed-property mutants have separate passing baseline logs (exit 0)
  and compiled target assertion failures (exit 101): replay cannot renew,
  outbox-full whole-round rollback, duplicate original-time retention,
  durable retry due, and wrong receipt retention. Source bytes were restored
  after each mutant (`raw/mutations-run.log`, `raw/mutations/`).
- The supervisor independently ran the durable binary's 12 tests at exit 0:
  `/home/tomi/nhm-supervision/c03-independent-durable.log`, SHA-256
  `fc043dbba9a23abf1f15a5542393baad97bc87690eca1bcdddffffbf7d6786ae`.
  This is an extra review receipt, not production acceptance.

## Actual isolated chain

The final run is `raw/runtime-chain-final.log` and `raw/runtime-final/`.
`start-receipt.json` freezes the runtime script, M/O binaries, Prometheus,
Alertmanager, rules, operational flags and exact generated configs before
process start; the harness verifies the input hashes again before success.
`timeline.json` has accepted receiver rows; `timeline-partial.json` includes
the `finally` cleanup stop events. All four isolated processes stopped and the
test exited naturally 0. No business service was started.

Prometheus-stop: its last genuine O sequence 22 arrived at
`1790674913.316`; 13 replayed old sequence webhooks returned
`accepted_sequences=0`. The direct outage notice was accepted at
`1790675020.317`, about 107.0 seconds after that last advancement. After
restart, O received new sequence 55 and then a healthy evaluation tick before
the next kill. Alertmanager-stop: a distinct pipeline notice was accepted at
`1790675155.372`, about 112.1 seconds after the last valid sequence 55;
restart produced new sequence 79 and another healthy tick. M-stop: a third
distinct process-unavailable notice was accepted at `1790675230.399`.
The direct receiver recorded four accepted HTTP notices with three unique
keys; the repeat of the first key is a bounded stable-key retransmission, not
a new outage.
All test identities were disposable and separated from V/A credentials.

The M-stop notice was about 60.0 seconds after the kill in the final run,
versus about 45.0 seconds in the earlier successful fifth run. The process
dead-man threshold remains 45 seconds after the last valid heartbeat, but O
evaluates every 15 seconds and a threshold landing just after a tick is
observed on the next tick. This is a timing review point, **not** a claim of
constant 45-second end-to-end notification. The pipeline threshold remains
100 seconds and was never relaxed. Steady healthy pipeline arrivals were
roughly 45 seconds apart with the fixed 15-second Prometheus resend flag;
startup and Alertmanager's in-flight post-kill drain are measured separately.

Historical lineage is retained: first chain failed at AM-stop recovery
causality; second failed to regain a new sequence under Prometheus's default
one-minute resend; third used a wrong tool path; fourth timed out 0.34 seconds
before the last genuine advancement reached the 100-second deadline because
AM drained an in-flight newer annotation after Prometheus stopped. Fifth
completed on the pre-Clippy allocation layout. None substitutes for the final
source-bound run. The original static rule-test expectation failure and first
Clippy failure are likewise not counted as successes.

## Remaining gates

Production source fixtures, C04 native roles/actions, C05 witness inputs,
C06 diagnostics, C08 persistent query/grants/MCP, C09 host placement,
retention/restore/soak and external human delivery are not accepted here.
The runtime receiver is an isolated mTLS test endpoint, not a production
receiver. O's own independent external dead-man placement and production
credentials still require deployment review. The evidence-only snapshot route
does not close live source inventory gaps or make pending rule adapters usable.

`SOURCE-SHA256SUMS`, `RAW-SHA256SUMS`, `BINARY-SHA256SUMS` and
`INDEX-SUMMARY.json` bind the candidate's source, raw receipts and exact
isolated binaries/tool archives.
