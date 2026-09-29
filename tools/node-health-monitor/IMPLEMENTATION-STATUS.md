# R4 implementation and acceptance ledger

Design: R4, memo blob `b6ee93b81ad3794eecff3b6c8ed2faf28072120c`.
Reviewed recovery checkpoint: `628d2967b1bccdab752e9fbe4b66087df68d18b4`.
The branch includes main commit `b9d8bc433c760f104a81cd1256581a4537923218`.
No C00–C09 stage is accepted. A checked item below means its named bounded
implementation and local tests exist, not that the whole stage or deployment passes.

| Work order | Delivered and locally tested | Still required before stage completion |
|---|---|---|
| C00 — implementing | ✅ 20 closed 2020-12 schemas, six-tool positive/negative contract fixtures; exact u64; frozen Python/Rust/C++ IPC vector; source/action/persistence/catalog manifests; sparse histogram series counting; production placeholder refusal; R4 semantic tests | Complete source catalog and actual source fixtures; full wire DTO/handler equivalence; catalog payload variants beyond the approved initial subset; MCP/Prometheus version and artifact pins; review of complete C00 output |
| C01 — implementing | ✅ Existing native actual-work admission, cache, collector completion and PQ counters; new standalone diagnostic wire codec; loopback typed `/health-snapshot` with exact generation, source epoch, frozen hash and PQ counters; bounded owner wait and actual lease retention | Feature-gated source rollout; remaining per-source timestamps; all collector contiguous-work/capacity evidence and full source/core publication tests |
| C02 — implementing | ✅ Optional fixed loopback native sampler; cached `/metrics`; 1,000 HTTP reads cause no extra native calls; minimum interval; same-generation stale/conflict protection; process sampler; nonempty query rejection; exact header/body generation pairing and initial process/native PQ R4 snapshot; fixed-role private-CA mTLS ingress with leaf ACL and bounded transport; scheduled mTLS management reachability probe | Full R4 SourceEnvelope/edge DTO migration; full heartbeat connection isolation; approved cgroup/host/readiness adapters; getStats remains unsupported |
| C03 — implementing | ✅ Deterministic multisource recovery contract; SQLite WAL/FULL control/evidence storage components; immutable sequence/watermark; persistent conflict quarantine; atomic incident/outbox; restart-to-unknown; evidence quota failure leaves control usable; independent health-state executable with 18-rule fact catalog, bounded control/evidence writers, whole-round transaction, immutable inventory revisions and database network binding, multiple-epoch live conflict quarantine and receipt-matched durable outbox; separate process/pipeline watchdog deadlines; scheduled native PQ fact adapter and immutable typed evidence relay | Complete real source adapters and collector/query durable integration; persistent grants/ledger; retention and migration/backup; actual Prometheus/Alertmanager/dead-man/independent receipt integration |
| C04 — implementing | ✅ Existing production PQ sign/verify hooks; real stage anchors and persistence ordering documented; contract vote-order/replay tests | Actual proposal/notarize/finalize/skip request/pending/outcome instrumentation and dedupe; queue/session teardown facts; storage hooks and restart proof; trace-off native integration tests. Contract vote model is not production instrumentation |
| C05 — implementing | ✅ Complete block-identity comparison primitive; canonical unsigned shard/hash validation; existing heartbeat replay test | Witness adapters and schedule; inventory genesis/role binding; five evidence dimensions; proof verifier separately unsupported; independent observer notification tests |
| C06 — implementing | ✅ Bounded ring primitive; frozen datagram codec; independent JSON/decoded diagnostic batch limits | Real producer early gate, authenticated nonblocking IPC, edge relay, persistent batch ingest and idempotent ACK; actual slow/dead consumers, disk-full and shutdown integration |
| C07 — not_started | No provider enabled | Fixed immutable evidence package; approved AURA/model integration, actual provider validation, private egress and resource-isolation tests |
| C08 — implementing | ✅ Existing cache query/grant primitives; strict request validation; HTTP failures no longer return successful 200 | Full output DTOs enforced in runtime, persistent run ledger, stable authorized cursors/ancestors/materialized aggregates, MCP SDK, model/child cancellation, run-wide byte/token budgets and actual zero-upstream integration |
| C09 — not_started | ✅ Development contracts and examples fail production readiness without evidence | Approved host/failure domains, credentials/receiver, effective quotas; A–F raw monotonic performance profiles; rotation/rollback/restore and 72h soak. No runtime deployment acceptance |

## Evidence mapping

- `crates/health-core/tests/contracts.rs`: prior 30 deterministic behavior tests.
- `crates/health-core/tests/r4.rs`: 16 exact-integer, IPC, monotonic freshness,
  multisource recovery, metric-capacity, vote-order and deployment-refusal tests.
- `crates/health-services/tests/http.rs`: 10 credential/cache/query HTTP tests.
- `crates/health-services/tests/native_cache.rs`: 5 cache/schedule/bounds tests,
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
- `crates/health-services/tests/ingress.rs`: 3 real private-CA TLS integration
  tests, including valid/missing/expired/unapproved identities, role paths and
  scheduled mTLS probe identity validation.
- `crates/health-services/tests/watchdog.rs`: firing/monitor/epoch/sequence webhook
  acceptance. Pure clock tests independently establish the 45/100-second deadlines.
- `tests/runtime-mutations.py`: 24 additional compiled behavioral mutations.
- The existing 10 Rust and 6 C++ mutations remain in CI.

## Runtime boundaries

`health-state` now wires SQLite storage into an independent executable with
bounded writers and cached read endpoints. Its fixed catalog operates on closed
internal facts; management reachability and native PQ signing failures are connected here.
The existing `tos-observability` HTTP process still uses its bounded memory store.
Do not claim that its grants/results survive restart, that the internal FactFrame
replaces full R4 SourceEnvelope DTOs, or that all native rules receive real facts.
Prometheus rules and Alertmanager examples exist, but actual runtime integration
is not_run: binary download failed in this environment. mTLS local tests do not
establish production network/failure-domain isolation or human notification delivery.

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


Recovery evidence: 94 Rust tests, clippy with warnings denied, six exact native
contract mutants and ten typed service mutants. The initial R4 snapshot is a
closed subset, not a declaration that every source/capabilities handler is migrated.
See VALIDATION-R4.md for the distinction between pre-cleanup and reconstructed builds.
