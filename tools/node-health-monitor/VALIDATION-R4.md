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

### Recovered Rust native service wiring

The restored Rust workspace passes 94 tests and all-target clippy with warnings
denied. The service fixture covers real HTTP sampling, typed edge routing,
1,000 cache-only reads, mismatch/no-retry behavior, source age plus request time,
sticky conflicts, missing PQ quality, immutable evidence relay and source bounds.
`scheduled_native_poll_checks_inventory_over_mtls` uses real TLS sockets and
checks that the negative inventory case actually reached the upstream source.
`tests/native-typed-mutations.py` compiled and killed 10 corresponding mutants;
all source files were restored before the complete regression was rerun.

This adds only the initial process/native PQ R4 subset. It does not complete all
R4 capabilities, duties, storage, witness or production acceptance gates.

## C00 reconciliation and closure candidate (2026-09-29)

Starting branch commit: `0a3aafda25ad9fa9d93be45156e2df2838646085`.
Normative memo: `main@6c0536c042405e857bdced8e327b6f018c816526`;
design blob `c28a6b2506c98fc728f868081a8192f7d0cd0d0a`; work-order blob
`f7cd3371c8023bb61409d5e77fd96a3741f0cddd`.

This round preserves the existing foundation and closes the concrete C00 gaps.
All six query routes now construct closed typed outputs from cached records. The
handlers validate truthful quality, coverage, source version, payload hash,
redaction, metadata and finite/exact values. Unknown coverage returns unavailable;
partial coverage returns partial plus missing-evidence summaries. Unsupported
derived evidence fails because the current store has no lineage columns.
Heterogeneous metric metadata, labels, units, populations or epochs fails closed.
Coverage aggregation is stable-deduplicated and refuses per-series or response-wide
overflow instead of truncating evidence.

The locked closure entry point validates six actual non-null handler outputs and
a 64-missing-field/32-gap HTTP boundary against the published schemas. It then
runs the real production doctor, which exits nonzero for exactly 11 unverified
gates, and the 97-test workspace. Formatter and all-target Clippy with warnings
denied pass. Six targeted mutations compile and fail their exact assertions;
baseline and mutant raw logs are preserved separately with finite timeouts.

The source manifest is complete only as a C00 truth inventory. It contains all
16 required source classes, including explicit unsupported host/cgroup,
readiness, guard, witness and diagnostic entries. `complete_manifest` and
`production_adapter_inventory_complete` remain false. Existing isolated exporter
actor fixtures retain synthetic provenance; no business-node fixture was created.
MCP/rmcp and Prometheus artifacts are pinned but disabled: runtime gates remain
C08 and C03 respectively.

No business service was started, deployed or regenerated. No production node,
key, consensus path or database was touched. This is a review candidate, not a
self-acceptance of C00. Exact commands, failures, hashes and not-run gates are in
`evidence/c00-closure/C00-CLOSURE-EVIDENCE.md`.

### Reconstructed C++ publisher checkpoint

The current source rebuilt `test-health-native-snapshot` with Clang 21.1 and
passed its unit test plus fast, slow, disabled and retained-lease HTTP scenarios.
The fixture instantiates the production exporter actor and collector boundary.
It verifies 1,000 cache reads cause no extra collections, a two-second owner
response deadline, late-result rejection, actual-work lease retention, exact
u64 pairing, frozen hash and the corrected single-underscore histogram names.

All nine new C++ mutations compiled and failed their named assertions: network
lowercase, disabled endpoint, histogram name, exact u64, age, immutable alias,
read-without-collection, owner deadline and lease retention. The first two and
remaining seven ran in separate batches after a validation process interruption;
the runner restored sources and rebuilt the final native target. The existing
49 Rust and seven C++ mutations were also rerun successfully. Together with the
16 new Rust mutations this is 81 distinct compiled-and-failed mutations.

The changed validator-engine translation unit passed a syntax-only compile with
its actual build flags. The reconstructed full validator executable has not yet
been relinked at this checkpoint; the earlier pre-cleanup full build is not
claimed as validation of this recovered source tree. No deployment/performance
or 72-hour acceptance is implied by the isolated actor fixture.

### Reproducible native source fixture

The frozen JSON/OpenMetrics pair was recaptured from the reconstructed C++ actor
binary after source restoration. `native-snapshot-http.py --mode fast
--write-fixtures BUILD/test-health-native-snapshot` regenerates both files only
after exact generation, hash and schema validation. The native contract, typed
service and mTLS integration tests pass with the new pair. The source manifest
pins `NativeCorePublisher` to commit `d27f534d66be28a0753da1ef912df3fb1effba2e`
and labels the fixture as synthetic actor data, not a production-node capture.
The manifest remains incomplete and its performance gate remains `not_run`.
