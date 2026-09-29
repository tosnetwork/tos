# R4 continuation validation

Design fetched from memo/main: R4 blob
`b6ee93b81ad3794eecff3b6c8ed2faf28072120c`; work-order blob
`f7cd3371c8023bb61409d5e77fd96a3741f0cddd`.
TOS starting HEAD: `86db5fe9e93fe0a04c324dc0aa58dcfe88ce4b9f`.
The consensus/persistence anchors remain unchanged relative to the design's
`1620db717cb4ec4c0521fb9742338962eec1a5bd` baseline; the earlier branch adds
metrics/PQ hooks and exporter/QUIC collection protection.

## Commands and evidence

```sh
python3 tools/node-health-monitor/scripts/check-contracts.py
cargo fmt --manifest-path tools/node-health-monitor/Cargo.toml --all -- --check
cargo clippy --manifest-path tools/node-health-monitor/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path tools/node-health-monitor/Cargo.toml --locked --workspace
cargo build --manifest-path tools/node-health-monitor/Cargo.toml --locked
python3 tools/node-health-monitor/tests/process-smoke.py
python3 tools/node-health-monitor/tests/mutations.py
python3 tools/node-health-monitor/tests/native-mutations.py
python3 tools/node-health-monitor/tests/r4-mutations.py
```

67 Rust tests pass: 30 existing core, 16 R4 core, 10 HTTP, 6 SQLite and 5 native
cache tests. Contract validation covers 20 closed schemas, six tool request/error
response fixtures, unknown nested fields, exact u64 and UTCZ. It also compiles
and executes the standalone C++ codec; its bytes match Python and the Rust test.
The process smoke starts actual edge/query executables, imports a process sample,
queries with the authorized grant and confirms that revocation returns 401.

Mutations: 10 existing Rust + 6 existing C++ + 15 new Rust + 1 new C++.
An initial epoch-change mutation survived because the test used a smaller new
generation, which independently triggered the stale-generation check. The test
now uses a larger generation in the new epoch and fails when epoch reset is
removed. The repaired mutation is included in the final passing mutation run.

The new tests exercise production Rust library functions, actual SQLite files,
a real loopback HTTP source and real router requests. The vote stage model is
explicitly only a contract fixture; it is not a native consensus integration test.

## Limits and not-run gates

- No full validator build was needed for this round's standalone codec-only C++
  addition. The codec was compiled and run, including its mutation. Earlier native
  hooks were not extended by this round.
- The R4 output schemas are contract artifacts; existing handlers have not yet
  migrated to all those data shapes. Schema validation does not prove runtime
  DTO parity or all source adapters.
- SQLite tests establish the local component contracts, not wiring into the HTTP
  service, a complete inventory/rule engine, long-reader behavior or all disk faults.
- Native storms establish zero additional local requests for cached GETs, not
  production mTLS authorization, host isolation, all RPC sources or AI/MCP storms.
- No actual Prometheus/Alertmanager version tests, AURA/MCP sessions, model egress,
  witness proof validation, approved hardware performance measurements or 72h soak.
- No production deployment, restart, protocol change, durability change or real
  notification was performed. Production readiness remains blocked explicitly.


## Independent runtime continuation (2026-09-29)

Starting commit: `1774d2375005d58f88a75437486330ca5fafb8dd`; latest fetched memo
blob `8d406b3213ca6b9b1f123dcf31ef26f1aa318289` (normative R4 unchanged).
The earlier component-only limits above describe the previous round; the following
is the additional runtime boundary, not a complete C00–C09 acceptance.

Changed boundaries and their failing instruments:

| Boundary | Actual execution and sensitivity |
|---|---|
| Rule decisions | 8 Rust tests cover declared sources, complete fact catalog, monotonic freshness, counter baseline/epoch, distinct bad samples, pending time and scalar predicates; compiled mutations remove the relevant decisions |
| Transactional control | Real SQLite tests force the second rule's outbox write to fail; no rule, notification or evaluation sequence commits; inventory revisions are immutable and an existing revision remains restartable at history capacity |
| Runtime persistence | A test launches the actual `health-state` executable, ingests bad evidence over authenticated HTTP, kills it, restarts it and checks episode/severity/unknown plus persisted outbox; deleting persisted incidents on startup makes this test fail |
| Live conflict and delivery | Separate DB threads, real HTTP receipt server, mismatched then matching receipt; conflicting source identity changes a live open incident to suspended_unknown with unchanged severity; overlapping conflicts from old and current epochs remain isolated; removing quarantine/history or receipt matching fails assertions |
| mTLS boundary | Generated private CA/server/client/expired certificates, actual TLS sockets and upstream call count; the same unapproved leaf is first proven usable on an authorized control listener, then denied on the tested ACL; removing fingerprint or role checks fails |
| Queue age | Monotonic writer/queue residence is added with checked arithmetic before rule admission; duplicate immutable identity is preserved and overflow is rejected; removing residence age fails the test |
| Probe | Real mTLS edge and ingest routes exercise the scheduled probe; a different node identity produces incomplete/unknown facts, never consensus health; removing node matching fails |
| Observer | Process and pipeline clocks use independent 45/100-second deadlines; repeated sequence and retired epoch cannot refresh; actual webhook parsing rejects another monitor, resolved alerts and noncanonical sequence |
| Storage isolation | Symlink and hardlink aliases cannot map the control and evidence owners to one database; persisted network identity prevents reusing either database on another network; removing either check fails |

Run the earlier commands plus:

```sh
python3 tools/node-health-monitor/tests/runtime-mutations.py
```

The new runtime mutation runner is included in CI and restores each source in
`finally`. Initial certificate-ACL and probe-node mutants unexpectedly passed and were not
accepted as evidence. A fresh non-incremental probe build failed correctly. All
Rust mutation runners now explicitly disable incremental compilation. The TLS
fixture also establishes successful authorization of the same leaf before its
negative ACL check. The final runner requires every mutant to compile and fail
its named behavioral assertion; build failure never counts as a killed mutation.

Prometheus/Alertmanager examples and `tests/fixtures/rule_test.yml` are provided,
but real promtool and the full Alertmanager chain remain **not_run**. Release
binary downloads failed at the network proxy. YAML existence is not PromQL or
notification-chain acceptance. No human-delivery or production credential test
was performed. AI/MCP, actual native duty instrumentation, full typed native
snapshot/source adapters, witness collection, retention/grants/ledger, effective
host budgets, A–F performance, restore/rotation and 72h soak remain outstanding.


Final local result: **84 passing Rust tests**, clean formatter and Clippy,
20-schema/cross-language contract check, real edge/query process smoke, and
**56 compiled-and-failed mutations** (49 Rust, 7 C++). The full mutation suites
ran without incremental compilation; after the final network/quarantine change,
the three additional boundary/queue mutations and affected receipt/live-quarantine/process-restart
mutations were rerun, followed by the full 84-test workspace regression. There
was no production deployment and no real Prometheus/Alertmanager or soak pass.

## Native contract recovery checkpoint (2026-09-29)

The scratch source tree was removed by workspace maintenance before the preceding
native integration work was committed. This checkpoint restores the Rust native
contract only. Earlier full native build and integration logs do not prove that
this reconstructed tree contains that integration; native publisher, sampler and
manager wiring remain separate work.

Boundary-to-test mapping in `health-core/tests/native_contract.rs`:

- Exact decimal counters, header generation, inventory identity and content/body
  pairing: `exact_pairing_rejects_changed_generation_and_content`.
- Explicit nullable fields and closed payloads:
  `required_nullable_and_unknown_fields_are_enforced`.
- Source age and instrumentation quality:
  `age_and_quality_cannot_be_fabricated`.
- Stable content identity, excluding only receipt time and source age:
  `immutable_identity_excludes_only_receipt_and_age`.

All four tests pass. `tests/native-contract-mutations.py` compiled and killed six
mutants (generation, content hash, required nullable, source age, quality and
immutable metadata). Compilation failure is not accepted as a killed mutant.
The JSON/OpenMetrics fixture was recaptured from the surviving isolated C++ test
executable; it is not a production-node fixture or proof of the lost C++ source.
The fixture deliberately carries a PQ counter above the exact floating-point
integer range. No validator was deployed or restarted.
