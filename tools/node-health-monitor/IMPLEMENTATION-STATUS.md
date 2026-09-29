# R4 implementation and acceptance ledger

Design: R4, memo blob `b6ee93b81ad3794eecff3b6c8ed2faf28072120c`.
Reviewed code baseline: `86db5fe9e93fe0a04c324dc0aa58dcfe88ce4b9f`.
No C00–C09 stage is accepted. A checked item below means its named bounded
implementation and local tests exist, not that the whole stage or deployment passes.

| Work order | Delivered and locally tested | Still required before stage completion |
|---|---|---|
| C00 — implementing | ✅ 20 closed 2020-12 schemas, six-tool positive/negative contract fixtures; exact u64; frozen Python/Rust/C++ IPC vector; source/action/persistence/catalog manifests; sparse histogram series counting; production placeholder refusal; R4 semantic tests | Complete source catalog and actual source fixtures; full wire DTO/handler equivalence; catalog payload variants beyond the approved initial subset; MCP/Prometheus version and artifact pins; review of complete C00 output |
| C01 — implementing | ✅ Existing native actual-work admission, cache, collector completion and PQ counters; new standalone diagnostic wire codec | Feature-gated source rollout; loopback typed `/health-snapshot` sharing publisher generation; per-source timestamps; all collector contiguous-work/capacity evidence and full source/core publication tests |
| C02 — implementing | ✅ Optional fixed loopback native sampler; cached `/metrics`; 1,000 HTTP reads cause no extra native calls; minimum interval; same-generation stale/conflict protection; process sampler; nonempty query rejection | Full R4 SourceEnvelope/edge DTO migration; typed generation pairing; mTLS role ACL and heartbeat reservation; approved cgroup/host/readiness adapters; getStats remains unsupported |
| C03 — implementing | ✅ Deterministic multisource recovery contract; SQLite WAL/FULL control/evidence storage components; immutable sequence/watermark; persistent conflict quarantine; atomic incident/outbox; restart-to-unknown; evidence quota failure leaves control usable | Wire durable components into the collector/query/health-state processes; bounded writer executors and complete rules; persistence of inventory/grants/ledger; retention and migration/backup; actual Prometheus/Alertmanager/dead-man/independent receipt integration |
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
- `crates/health-services/tests/durable.rs`: 6 actual SQLite file tests covering
  restart, immutable pages, scope identity/conflict, atomic outbox and quota isolation.
- `scripts/check-contracts.py`: validates generated contracts and source anchors;
  compiles and executes the C++ codec against the Python/Rust frozen bytes.
- `tests/r4-mutations.py`: 15 compiled Rust mutations plus one compiled C++ mutation.
  Every named baseline must pass, every mutant must compile and fail its named
  behavioral test. Build failure does not count as a killed mutation.
- The existing 10 Rust and 6 C++ mutations remain in CI.

## Runtime boundaries

The new SQLite components are tested storage building blocks; the existing
`tos-observability` HTTP process still uses its bounded memory store. Do not
claim that those HTTP grants or results now survive restart. There is no
production `health-state` process or full rule package yet.

`health-edge` accepts an optional fixed numeric loopback native address. It is
the only owner within that process; all `/metrics` consumers read the completed
cache. Deployment must revoke old direct scrapes and prohibit duplicate edge
owners. The code does not prove a remote deployment has done this. The legacy
native float generation marker is rejected above 2^53−1; exact typed native
snapshots are still outstanding. Local age conversion assumes the native and
edge wall clocks refer to the same host and rejects future/stale timestamps.

Only the synthetic catalog 7/type 1 has a frozen diagnostic payload. No existing
trace is sent through this codec, and it is not a production trace schema.
Source fixtures that have not been captured remain null with contract_valid=false.
The PQ metric manifest is an initial sparse catalog, not a complete core profile.

No production validator was deployed, restarted or fault-injected. No signing,
vote-journal ordering, database durability or protocol condition was changed.
