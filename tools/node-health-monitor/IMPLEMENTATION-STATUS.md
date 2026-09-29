# R3 implementation and acceptance ledger

This ledger distinguishes implemented primitives from integrated sources and
runtime acceptance. No row below is a claim that H0–H6 are complete.

| Phase | Delivered in this branch | Outstanding |
|---|---|---|
| H0 | Spec/blob/base binding; initial source anchors; source semantics and bounded primitives; reproducible test commands | Complete frozen source/duty/point/proof manifests, fixtures for every existing source, actual host inventory and hardware profiles, per-actor contiguous-work budget |
| H1a | Exporter actual-work admission/cache; bounded async batches; summary-only QUIC metrics; process edge and fixed collector; basic cache-query service and watchdog code | Full source latency/capacity protection, getStats/admin adapters, mTLS ingress/ACL, HA ownership/fencing, durable storage, complete rules/inventory disappearance handling, actual independent notification receipt |
| H1b | Production consensus PQ hooks and fixed histograms; tested duty/guard primitives | Hook actual assigned/eligible/started/terminal/deadline duties; cancellation/restart cohorts; persistence completion semantics and hooks; queue/session/resolver lifecycle sources; role/scope manifests; stage/PQ queue histograms |
| H2 | Full block-identity comparison primitive and heartbeat replay tests | Real witness/non-voting-node adapters, evidence/proof validation, coverage accounting, independent failure-domain and notification testing |
| H3 | Bounded native diagnostic ring primitive | Trace producer early-disable/sampling migration; IPC/pump/relay; ingest/retention; global budgets; drop provenance; slow-consumer/ENOSPC integration tests |
| H4 | Cache query primitives/HTTP, run grants and ledgers in memory, broker cancellation model, strict diagnosis validation | Persistent run ledger; exact full envelopes/quality contracts across all backends; pagination/aggregates/ancestors; MCP Rust SDK sessions; AURA provider integration; model/context/token accounting; child cancellation; actual zero-upstream and M-protection tests |
| H5 | No enablement | Optional provider/API/CLI bridges and service-specific index/RPC extensions |
| H6 | CI and repeatable local checks | Real upgrade/rotation/notification/expiry/recovery exercises, 72h soak, performance acceptance on approved hardware |

## Native behavior changes

`/metrics` now returns 503 until a successful generation is ready, and returns
503 when the last successful generation is older than 30s. Valid cached
responses preserve generation and original completion timestamp. Requests can
start a collection only at the admitted interval; none waits on it. A result
finishing after the 2s source budget is rejected for publication, and its
actual-work token is not released before completion. This does not yet cancel
or preempt a slow individual collector.

Per-path QUIC metrics disappear from the native metrics scrape by design;
`collect_stats()` callers outside this path retain detailed stats. Individual
server connection traversal still needs an approved contiguous-work budget
and batching validation before production acceptance.

`--health-core-metrics` currently enables only process-wide consensus PQ
operation metrics. Sign calls cover `ValidatorPQKeyStore::sign_consensus`;
verify calls cover `PeerValidator::check_signature`. It must not be described
as all PQ cryptography or complete validator duty health. Snapshots are
concurrent approximate reads, not a global atomic snapshot.

## Evidence boundaries

- Unit/HTTP tests do not establish physical isolation, notification delivery,
  chain safety or performance overhead.
- A source-code anchor establishes where a fact is produced, not that a
  deployed instance has enabled it.
- The default acceptance file contains only false values. Production must
  remain unapproved until implementation and runtime evidence close each gate.
- A compiled test that fails after removing its guard provides sensitivity
  evidence for that guard. It does not cover unrelated unfinished components.
