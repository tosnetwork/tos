# Remaining rule adapters (2026-09-30, afternoon)

Owner instruction: implement the rules that were still `pending_C04`. State
of the 18-rule catalog after this work, as evaluated on the six local nodes:

| Rule | Fact | Source id (fact frame) | Adapter | Live input |
| --- | --- | --- | --- | --- |
| target_unreachable | Reachable | edge_probe | implemented (earlier) | good ×6 |
| telemetry_unavailable | — | inventory | implemented (earlier) | good ×6 |
| local_chain_stalled, pq_signing_failure, local_action_failure, storage_ack_failure | derived | native_facts | implemented (morning) | good ×6 |
| local_action_overdue, session_stop_pending | derived | native_facts | implemented (morning) | good ×4 validators |
| **initialization_stalled** | InitializationPendingMs | native_facts | **implemented**: ms since the first sample of the process epoch until a consensus session is active or the applied chain advanced within 60 s | good ×4 validators |
| **applied_served_gap** | AppliedServedGap | native_chain | **implemented** (v3 anchors, only when the node serves lite state; otherwise no fact, never zero) | good ×6 |
| **diagnostic_coverage_reduced** | DiagnosticDrops | diagnostic | **implemented**: producer + relay drops + parse errors of the native publisher, Increase within an epoch | good ×6 |
| **memory_growth_unexplained** | UnexplainedMemoryBytes | process_facts | **implemented**: anonymous memory growth of the node process over a trailing 15-minute window from the edge's process source | good ×6 |
| **quic_pressure** | QuicBacklogBytes | native_gauges | **implemented**: `tos_quic_summary_unsent_bytes + unacked_bytes` read from the edge's cached OpenMetrics (two exact metric names, nothing else parsed) | good ×6 |
| queue_stall | QueueOldestMs | native_queues | **implemented (night)**: the validator manager's three real waiter queues (block data, state incl. preliminary, shard client) with per-waiter creation time; the PQ signer still has no queue and none is invented | good ×7 (live 00:32 UTC: depth 0, oldest wait 0) |
| **duty_missed** (night) | DutyWindowsMissed | native_duties | **implemented**: leader windows the collator schedule assigned to this node minus started, superseded and finality-suppressed ones; membership published beside it | good ×5 validators (136 windows assigned, 136 started, 0 missed) |
| **storage_space_low**, **state_gc_lag** (night) | DiskUsedPermille, StateGcLagBlocks | native_storage | **implemented**: `statvfs` of the database root; applied seqno minus the GC seqno, persistent-state seqno beside it | good ×7 (disk 445 ‰ used; GC lag 21,964 blocks and rising until the first persistent state) |
| rocksdb_write_stopped | RocksdbWriteStopped | native_gauges | **implemented (later that afternoon)**: RocksDB records `rocksdb.is-write-stopped` after every synchronous commit into `td::storage_health`; the exporter publishes `tos_health_storage_write_stopped`; the poller adds it to the gauges frame. Needs engine `validator-engine-nhm-cc-3fd4164d7687edf3` or later | good on the nodes running that engine, unknown (frame incomplete) elsewhere |
| **key_block_stale** (added in the evening) | KeyBlockAgeMs | native_key_block | **implemented**: the validator manager publishes the last known key block with the v3 anchor; age from the anchor's own clocks; threshold 1 h on the rotating network | good ×7 (key block every ~10 min) |
| observer_disagreement | ObserverDisagreement | witness | **implemented (later that afternoon)**: `health-witness-compare` reads M's archived v3 anchors and compares each node against the observers (fork at an equal seqno; lagging every fresh observer head by more than 150 blocks); no fresh anchor pair, no fact | good ×6 on a live chain; unknown while a node replays |
| monitoring_unavailable | watchdog | — | direct notice only (unchanged) | — |
| ai_unavailable | AiAvailable | ai_optional | **implemented (later that afternoon)**: the judgement posts an availability fact for the `monitor` target after every model turn | bad/open whenever the local Codex is at capacity; good after an accepted analysis |

Thresholds in the local inventory (`development-native-facts-4`):
initialization 600 s, applied/served gap 64 blocks, memory growth 4 GiB /
15 min, QUIC backlog 64 MiB, each with two bad samples and a 60 s hold.

## Defects the rollout exposed, all fixed

1. Upgrading the derived-fact catalog (7 → 8 facts) inside a running process
   epoch produced a second, different body for an already archived generation
   under the shared `native_core` source id. M did what the contract says and
   quarantined that (node, epoch, source) — which also refused the collector's
   archived snapshots for five nodes. Fix: derived facts are their own source
   (`native_facts`) and their source epoch carries the catalog version
   (`…:facts-v2`), so a derivation change is a new epoch, never a conflict
   with the archived snapshot. The five stale quarantine rows were cleared by
   operator action with a receipt (`runtime/quarantine-clear-*.json`), and the
   manager admits both ids for the seven native rules.
2. The same collision, one hour later, for the process memory fact posted
   under the archived `process` source id: six quarantine rows, collectors
   refused, the judge reported every node unobservable. Fixed the same way
   (`process_facts` + catalog version in the source epoch), rows cleared by
   operator action with a receipt. Rule recorded: **a derived fact frame
   never reuses an archived source id.**
3. With five fact lanes per node the six pollers' synchronized ticks hit the
   manager's ingest admission (four in-flight requests, immediate 429):
   pollers now re-phase by a fixed per-node offset after their first sample,
   the admission bound is 16 (the single evidence writer stays the real
   bound), and a poller retries a shed request once after 250 ms. Result on
   the live network: 0 refusals, 0 collector errors, every rule input `good`.
4. `manual_range_contains` lint in the gauge parser.

Gates on the final tree: see the commit; `check-contracts.py` 24 schemas OK.
