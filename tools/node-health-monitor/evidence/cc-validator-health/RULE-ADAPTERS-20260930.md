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
| **memory_growth_unexplained** | UnexplainedMemoryBytes | process | **implemented**: anonymous memory growth of the node process over a trailing 15-minute window from the edge's process source | good ×6 |
| **quic_pressure** | QuicBacklogBytes | native_gauges | **implemented**: `tos_quic_summary_unsent_bytes + unacked_bytes` read from the edge's cached OpenMetrics (two exact metric names, nothing else parsed) | good ×6 |
| queue_stall | QueueOldestMs | — | **unsupported**: the PQ signer is synchronous, there is no queue (`pq_queue: synchronous_signer_no_queue`); no value is invented | — |
| rocksdb_write_stopped | RocksdbWriteStopped | — | **unsupported**: the engine gathers `rocksdb.is-write-stopped` into its console stats string only; nothing exports it and the edge RPC lane is off by contract | — |
| observer_disagreement | witness | — | pending_C05 (unchanged) | — |
| monitoring_unavailable | watchdog | — | direct notice only (unchanged) | — |
| ai_unavailable | ai_optional | — | pending_C08 (unchanged) | — |

Thresholds in the local inventory (`development-native-facts-3`):
initialization 600 s, applied/served gap 64 blocks, memory growth 4 GiB /
15 min, QUIC backlog 64 MiB, each with two bad samples and a 60 s hold.

## Two defects the rollout exposed, both fixed

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
2. `manual_range_contains` lint in the gauge parser.

Gates on the final tree: see the commit; `check-contracts.py` 24 schemas OK.
