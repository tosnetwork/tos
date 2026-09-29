# R4 implementation and acceptance ledger

Design: R4, current design blob `c28a6b2506c98fc728f868081a8192f7d0cd0d0a`
from memo `main@6c0536c042405e857bdced8e327b6f018c816526`.
Reviewed recovery checkpoint: `628d2967b1bccdab752e9fbe4b66087df68d18b4`.
The branch includes main commit `b9d8bc433c760f104a81cd1256581a4537923218`.
C00–C04 have scoped development acceptances. C05–C08 have bounded development
implementations; C09 has a local observability deployment and a scoped live-data
receipt, not production or 72-hour acceptance. A checked item means only its
named implementation and evidence exist, never a main merge.

| Work order | Delivered and locally tested | Still required before stage completion |
|---|---|---|
| C00 — accepted (contract/inventory/test-entry scope only) | ✅ Supervisor accepted exact commit `87a36e95624726a6f72a31ff07ff8a8ff3b87056`: 20 closed schemas; concrete DTOs from all six real HTTP success handlers; schema-validated 64/32 aggregation boundary; malformed/overflow/heterogeneity/lineage negatives; exact u64; frozen Python/Rust/C++ IPC vector; complete C00 source-class truth inventory; sparse histogram counting; real 11-gate production-doctor refusal; hash-locked Python environment; disabled MCP/Prometheus artifact pins; six compiled-and-killed closure mutations | This decision is not production acceptance. Real provider adapters/fixtures stay disabled and move to C01-C05; durable MCP query transport is C08; Prometheus/Alertmanager runtime is C03; host/credentials/performance/soak remain C09. |
| C01 — accepted (bounded native publisher/registry/isolated contracts only) | ✅ Supervisor accepted exact commit `e460faa8403ae583bba21855abeb0e2ed81090ed` in memo `main@b9ed82ac091c48ebfd381b18208bb39175510da0`: source admission before fan-out; one owner waiter; 15-second schedule; 2-second owner deadline; child-drain lease; immutable exact-byte OpenMetrics/typed pairing; cache-only loopback snapshot; callback-time per-source status; 64-slot bounded registry skeleton; gate-off/per-path controls; real HTTP concurrency/disconnect/error/exact-2-MiB tests and nine valid compiled assertion mutations. Publication-time fields use `exporter_snapshot_collection_*`. | Scoped acceptance is not production/deployment/performance acceptance. Real production source fixtures, approved contiguous-work budget, host deployment, Prometheus runtime and C04 business hooks remain open. The original HOLD, retired alarm survivor and earlier failures remain historical evidence. |
| C02 — accepted (basic-only edge) | ✅ Supervisor accepted exact commit `a884b0ca735736fd5a81306c26bdc65a5bd967df`: fixed 15-second sampler, bounded typed cache routes, process/native/cgroup epoch binding, effective cgroup ancestor quotas, eight mTLS connections with classified seven-plus-one heartbeat reserve, actual slow-source/TLS/role and six mutation witnesses | Readiness and validator/getStats stay unsupported; no host deployment/performance acceptance. Preclassification occupancy is bounded by separate TLS/header phases, not an unconditional heartbeat guarantee. |
| C03 — accepted (basic-only state/rules/notification) | ✅ Supervisor accepted exact commit `2060cc1a1c7a36fe7214789a254cc36017c9f3a0`: WAL/FULL stores, persistent conflict and atomic outbox/timeline, 18-rule catalog, pinned Prometheus/Alertmanager checks and isolated stop/replay/receiver chain with five compiled mutation reds | Acceptance does not certify complete C04/C05 source adapters, production receivers, durable query grants, deployment or performance. |
| C04 — accepted (integrated development only) | ✅ Supervisor accepted exact commit `88d5d95ad98413e035c4fec04a68c6306b5bb26d`: native v2 actions/persistence accounting and strict consumer, 35/35 native tests, 48 actual publisher pairs, isolated compiled mutations and 132 active Rust tests | No production business node run; stopped remains null, native performance gate false, hardware durable finality/actor drain/queue denominators remain unsupported. |
| C05 — development candidate delivered | ✅ At `35ba59c111dd74518e6e661bcd1984598d493907`, bounded 32-target/16-endpoint cache witness, strict typed source/anchor and five-dimension qualification, O 15-second poll/cache and own-lane health, M historical archive plus separately qualified current view, same-host BOOTTIME transit, mTLS ingresses, budgets and negative controls were delivered with indexed evidence. | Production witness source/finality proof, actual external receiver, runtime cost and witness rule facts remain unsupported; this candidate does not establish verified finality or production acceptance. |
| C06 — integrated development implementation | ✅ Gated native diagnostic producer and bounded catalog-8 scalar payload, private authenticated native-to-Edge IPC, bounded relay, distinct M diagnostic ingest identity and single-writer durable batch/atomic idempotent ACK were integrated and tested. The catalog-7 fixture remains separate. | Business-node hook rollout and production cost/consumer-drain gates remain open; unknown diagnostic observation times remain null. M-to-Query diagnostic projection is unsupported, not a process fact. |
| C07 — bounded development package | ✅ Deterministic 16-KiB process-only package from verified retained M parents at fixed grant watermarks, durable private QueryLedger with 8-MiB cap, restart/late-row/conflict/missing/tamper controls and a closed diagnosis parser. No model/provider is enabled. | Actual model token accounting, semantic entailment, approved model/provider configuration, retention cleanup, private egress and resource-isolation acceptance remain open. The test-side deterministic judgment is not AURA model diagnosis. |
| C08 — gated transport implemented | ✅ Durable grants/cursors and six-tool private Unix MCP, a pinned AURA 0.12 stdio adapter, one-use credential handoff, bounded calls/body/session, child cancellation/reap and disconnect controls were exercised. Six real tool calls through AURA establish transport/error propagation; unavailable fixture tools did not become business successes. | Complete source adapters, production broker authorization/rotation and sustained resource/zero-upstream evidence remain open. External model calls remain disabled; transport success is not model judgment or production acceptance. |
| C09 — RED/open: local observability running, continuity blocked | ✅ M-only update, six role-split 15-second supervised collectors and an MCP-enabled local query broker archived six distinct live `process` sources without relabelling `edge_probe`. Pinned AURA 0.12 queried the already-running broker under fixed 4+2 grants: six `partial` snapshots contained non-null process values matching original retained M parent payloads; unknown consensus and cross-run denial remained explicit, and grants were revoked. Scoped process-payload closure was reviewed at `44186b022f454449ed58dce30c7fec5c71f24851` (raw SHA-256 prefix `cc4c95c8`). No model API or business-node restart was involved. | No production or 72-hour pass: the current M projection rescans process history from the beginning and rejects more than 4096 rows or 8 MiB, then revokes active grants. This deterministic growing-history limit and observed broker latency require a bounded, restart-safe fix before sustained AURA availability can pass. Raising that cap or timeout is not a fix. Also complete A–F monotonic resource/performance and failure-domain/effective-quota profiles, credential/receiver rotation, rollback/restore and 72-hour soak. A partial process snapshot is not whole-node health or model diagnosis. |

## Evidence mapping

- `crates/health-core/tests/contracts.rs`: prior 30 deterministic behavior tests.
- `crates/health-core/tests/r4.rs`: 16 exact-integer, IPC, monotonic freshness,
  multisource recovery, metric-capacity, vote-order and deployment-refusal tests.
- `crates/health-services/tests/http.rs`: 13 credential/cache/query HTTP tests,
  including all six non-null success DTOs and per-series/response-wide coverage boundaries.
- `crates/health-services/tests/native_cache.rs`: 6 cache/schedule/bounds tests,
  including a real loopback fake server and 1,000 router requests.
- `crates/health-services/tests/durable.rs`: 8 actual SQLite file tests covering
  restart, immutable pages, scope identity/conflict, atomic outbox, whole-round rollback, immutable inventory revision/capacity and quota isolation.
- `scripts/check-contracts.py`: validates generated contracts and source anchors;
  compiles and executes the C++ codec against the Python/Rust frozen bytes.
- `tests/r4-mutations.py`: 15 compiled Rust mutations plus one compiled C++ mutation.
  Every named baseline must pass, every mutant must compile and fail its named
  behavioral test. Build failure does not count as a killed mutation.
- `crates/health-core/tests/rules.rs`: 8 fixed-catalog, counter-baseline, source
  quality, pending-generation, inventory and replay tests.
- `crates/health-services/tests/manager.rs`: 4 integration/age tests for real process
  kill/restart, live conflict quarantine, receiver receipt and path-alias isolation.
- `crates/health-services/tests/ingress.rs`: 7 real private-CA TLS integration
  tests, including valid/missing/expired/unapproved identities, role paths,
  eight idle authenticated readers, seven draining ordinary responses plus
  classified EdgeReader/EdgeWatchdog heartbeat, and scheduled probe parsing.
- `crates/health-services/tests/cgroup.rs`: bounded fake cgroup-v2 hierarchy,
  tighter-parent, root-without-quota-files, current-above-limit pressure,
  unlimited/finite, symlink/zero refusal and capability-status tests.
- `crates/health-services/tests/edge_lifecycle.rs`: isolated `health-edge` exit
  leaves the configured synthetic source process alive.
- `crates/health-services/tests/watchdog.rs`: firing/monitor/epoch/sequence webhook
  acceptance. Pure clock tests independently establish the 45/100-second deadlines.
- `tests/runtime-mutations.py`: 24 additional compiled behavioral mutations.
- The existing 10 Rust and 6 C++ mutations remain in CI.
- `tests/c00-closure-mutations.py`: 6 targeted mutants. Each baseline passes;
  each mutant compiles and fails its named HTTP assertion within 120 seconds.
  Separate raw logs are under `evidence/c00-closure/mutation-logs/`.
- `tests/c02-edge-mutations.py`: 6 C02-only mutants for effective roots,
  pressure truth, epoch binding, both heartbeat admissions, classified
  connection lifetime and missed-tick skipping. Each compiles and reaches its
  intended assertion failure; raw baseline/mutant logs are indexed separately.

## Runtime boundaries

`health-state` uses SQLite bounded writers and cached read endpoints. Its fixed
catalog operates on closed internal facts; management reachability and native PQ
signing failures are connected here. Development C05 witness history/current state
and C06 diagnostic batches have separate durable paths; neither silently supplies
verified finality or a process observation. `tos-observability` now has a durable
private QueryLedger for bounded grants/results/cursors and an opt-in private Unix
MCP broker. Its verified live query projection is process-only. Do not claim that
the internal FactFrame replaces all R4 SourceEnvelope DTOs, that all native rules
receive real facts, or that witness/diagnostic archives are live query adapters.
Pinned Prometheus/Alertmanager rules and an isolated actual stop/replay/receiver
chain passed the scoped C03 review at `2060cc1a1c7a36fe7214789a254cc36017c9f3a0`.
Earlier binary-download and runtime red attempts remain historical evidence,
not the current gate result. That isolated chain and mTLS local tests do not
establish production network/failure-domain isolation or human notification
delivery.

`health-edge` accepts an optional fixed numeric loopback native address. It is
the only owner within that process; all `/metrics` consumers read the completed
cache. Deployment must revoke old direct scrapes and prohibit duplicate edge
owners. The code does not prove a remote deployment has done this. The legacy
native float generation marker is rejected above 2^53−1 in address-only mode.
With a configured network identity, exact typed snapshots are paired against the
OpenMetrics body and headers; source age includes request duration and cache
residence, and repeated generations cannot renew it. Legacy local age conversion
assumes both wall clocks refer to the same host and rejects future/stale timestamps.

The original synthetic catalog-7/type-1 diagnostic fixture remains frozen. C06
adds a gated native catalog-8 producer, private IPC/relay and durable M diagnostic
batch ingest; it does not certify a deployed business-node trace, a known event
observation time, or a QueryService diagnostic adapter. Source fixtures not actually
captured remain null with `contract_valid=false`. The PQ metric manifest is a
bounded sparse catalog, not a complete core profile.

C09 has deployed only local observability components: an M-only service update,
six supervised collectors and an MCP-enabled query broker over private sockets.
The existing business nodes and Edge processes were not restarted or fault-injected
for this work. The scoped pinned-AURA receipt proves six partial real process values
and their retained M parents, not whole-node health, AURA model judgment,
continuous availability, a 72-hour pass or production acceptance. One transient
collector `invalid edge response` recovered at a later sample; live-broker control
read latency also varied as its M database grew. Those observations remain open C09
soak/performance work, not zero-error claims. The M-to-query process import also
rescans oldest-first history in the **deployed** query binary; its 4096-row/
8-MiB cap will reject continued growth and revoke grants. An isolated candidate
now uses bounded, restart-safe pages and a durable global M cursor, with source-
bound tests in `evidence/c09-incremental-projection/REVIEW-RECEIPT.md`; it is not
deployed or a soak/performance pass. External model/API use is disabled.
No business-node signing, vote-journal ordering, database durability or protocol condition was changed.


Current C00 closure evidence: 97 Rust tests, clippy with warnings denied, six exact native
contract mutants and ten typed service mutants. The initial R4 snapshot is a
closed subset, not a declaration that every source/capabilities handler is migrated.
See VALIDATION-R4.md for the distinction between pre-cleanup and reconstructed builds.
