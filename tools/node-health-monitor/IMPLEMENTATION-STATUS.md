# R4 implementation and acceptance ledger

Design: R4, current design blob `c28a6b2506c98fc728f868081a8192f7d0cd0d0a`
from memo `main@6c0536c042405e857bdced8e327b6f018c816526`.
Reviewed recovery checkpoint: `628d2967b1bccdab752e9fbe4b66087df68d18b4`.
The branch includes main commit `b9d8bc433c760f104a81cd1256581a4537923218`.
C00–C04 have scoped development acceptances only; C05 is implementing. A checked
item means its named bounded implementation and tests exist, never production
deployment or a main merge.

| Work order | Delivered and locally tested | Still required before stage completion |
|---|---|---|
| C00 — accepted (contract/inventory/test-entry scope only) | ✅ Supervisor accepted exact commit `87a36e95624726a6f72a31ff07ff8a8ff3b87056`: 20 closed schemas; concrete DTOs from all six real HTTP success handlers; schema-validated 64/32 aggregation boundary; malformed/overflow/heterogeneity/lineage negatives; exact u64; frozen Python/Rust/C++ IPC vector; complete C00 source-class truth inventory; sparse histogram counting; real 11-gate production-doctor refusal; hash-locked Python environment; disabled MCP/Prometheus artifact pins; six compiled-and-killed closure mutations | This decision is not production acceptance. Real provider adapters/fixtures stay disabled and move to C01-C05; durable MCP query transport is C08; Prometheus/Alertmanager runtime is C03; host/credentials/performance/soak remain C09. |
| C01 — accepted (bounded native publisher/registry/isolated contracts only) | ✅ Supervisor accepted exact commit `e460faa8403ae583bba21855abeb0e2ed81090ed` in memo `main@b9ed82ac091c48ebfd381b18208bb39175510da0`: source admission before fan-out; one owner waiter; 15-second schedule; 2-second owner deadline; child-drain lease; immutable exact-byte OpenMetrics/typed pairing; cache-only loopback snapshot; callback-time per-source status; 64-slot bounded registry skeleton; gate-off/per-path controls; real HTTP concurrency/disconnect/error/exact-2-MiB tests and nine valid compiled assertion mutations. Publication-time fields use `exporter_snapshot_collection_*`. | Scoped acceptance is not production/deployment/performance acceptance. Real production source fixtures, approved contiguous-work budget, host deployment, Prometheus runtime and C04 business hooks remain open. The original HOLD, retired alarm survivor and earlier failures remain historical evidence. |
| C02 — accepted (basic-only edge) | ✅ Supervisor accepted exact commit `a884b0ca735736fd5a81306c26bdc65a5bd967df`: fixed 15-second sampler, bounded typed cache routes, process/native/cgroup epoch binding, effective cgroup ancestor quotas, eight mTLS connections with classified seven-plus-one heartbeat reserve, actual slow-source/TLS/role and six mutation witnesses | Readiness and validator/getStats stay unsupported; no host deployment/performance acceptance. Preclassification occupancy is bounded by separate TLS/header phases, not an unconditional heartbeat guarantee. |
| C03 — accepted (basic-only state/rules/notification) | ✅ Supervisor accepted exact commit `2060cc1a1c7a36fe7214789a254cc36017c9f3a0`: WAL/FULL stores, persistent conflict and atomic outbox/timeline, 18-rule catalog, pinned Prometheus/Alertmanager checks and isolated stop/replay/receiver chain with five compiled mutation reds | Acceptance does not certify complete C04/C05 source adapters, production receivers, durable query grants, deployment or performance. |
| C04 — accepted (integrated development only) | ✅ Supervisor accepted exact commit `88d5d95ad98413e035c4fec04a68c6306b5bb26d`: native v2 actions/persistence accounting and strict consumer, 35/35 native tests, 48 actual publisher pairs, isolated compiled mutations and 132 active Rust tests | No production business node run; stopped remains null, native performance gate false, hardware durable finality/actor drain/queue denominators remain unsupported. |
| C05 — implementing | ✅ Bounded development-only 32-target/16-endpoint cache witness, strict typed source/anchor and five-dimension qualification, O cache/15-second poll and own-lane health, M separate historical archive/current ordering, trusted-same-host BOOTTIME transit, two mTLS ingresses, negative controls and current-view budget checkpoint through `8699a3e554dcacdd0fd0194de4c823b1b34c6e20`; one compiled current-age sensitivity red with restored source | Production witness source/proof/receiver and runtime cost unverified; no witness rule fact or verified finality. Final source/evidence index and supervisor C05 review remain open. |
| C06 — implementing | ✅ Bounded ring primitive; frozen datagram codec; independent JSON/decoded diagnostic batch limits | Real producer early gate, authenticated nonblocking IPC, edge relay, persistent batch ingest and idempotent ACK; actual slow/dead consumers, disk-full and shutdown integration |
| C07 — implementing (development-only) | ✅ Deterministic 16-KiB process-only package from verified retained M parent at both fixed grant watermarks; restart/late-row/conflict/missing controls; closed diagnosis parser rejects blank claims/IDs and unsupported runbooks. No model/provider enabled. | Persist package as a broker run artifact; actual 8192-token accounting, semantic entailment review, approved AURA/model protocol, private egress and resource-isolation tests. No production/AI acceptance. |
| C08 — implementing | ✅ Cache query/grant primitives, durable ledger/stable cursors, opt-in six-tool rmcp transport through actual HTTP handlers, hidden run token, single-use connection binding, 16 calls, 32-KiB serialized response, 128-KiB response-body run cap and 180-second bound session; isolated SDK/Unix/restart tests. | Full AURA child lifecycle/cancellation and two-child accounting, complete source adapters and actual zero-upstream storm evidence; default feature stays off. No stage acceptance. |
| C09 — not_started | ✅ Development contracts and examples fail production readiness without evidence | Approved host/failure domains, credentials/receiver, effective quotas; A–F raw monotonic performance profiles; rotation/rollback/restore and 72h soak. No runtime deployment acceptance |

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

`health-state` now wires SQLite storage into an independent executable with
bounded writers and cached read endpoints. Its fixed catalog operates on closed
internal facts; management reachability and native PQ signing failures are connected here.
The existing `tos-observability` HTTP process still uses its bounded memory store.
Do not claim that its grants/results survive restart, that the internal FactFrame
replaces full R4 SourceEnvelope DTOs, or that all native rules receive real facts.
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

Only the synthetic catalog 7/type 1 has a frozen diagnostic payload. No existing
trace is sent through this codec, and it is not a production trace schema.
Source fixtures that have not been captured remain null with contract_valid=false.
The PQ metric manifest is an initial sparse catalog, not a complete core profile.

No production validator was deployed, restarted or fault-injected. No signing,
vote-journal ordering, database durability or protocol condition was changed.


Current C00 closure evidence: 97 Rust tests, clippy with warnings denied, six exact native
contract mutants and ten typed service mutants. The initial R4 snapshot is a
closed subset, not a declaration that every source/capabilities handler is migrated.
See VALIDATION-R4.md for the distinction between pre-cleanup and reconstructed builds.
